import NodeCache from '@cacheable/node-cache'
import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import { randomBytes } from 'crypto'
import { DEFAULT_CACHE_TTLS, WA_DEFAULT_EPHEMERAL } from '../Defaults'
import { MessageCache } from '../Utils/message-cache'
import type {
	AnyMessageContent,
	MediaConnInfo,
	MessageReceiptType,
	MessageRelayOptions,
	MiscMessageGenerationOptions,
	SocketConfig,
	WAMessageKey
} from '../Types'
import {
	aggregateMessageKeysNotFromMe,
	assertMediaContent,
	bindWaitForEvent,
	decryptMediaRetryData,
	delay,
	encodeNewsletterMessage,
	encodeSignedDeviceIdentity,
	encodeWAMessage,
	encryptMediaRetryRequest,
	extractDeviceJids,
	generateMessageIDV2,
	generateWAMessage,
	generateWAMessageFromContent,
	getStatusCodeForMediaRetry,
	getUrlFromDirectPath,
	getWAUploadToServer,
	normalizeMessageContent,
	parseAndInjectE2ESessions,
	unixTimestampSeconds
} from '../Utils'
import { getUrlInfo } from '../Utils/link-preview'
import { makeKeyedMutex } from '../Utils/make-mutex'
import {
	areJidsSameUser,
	type BinaryNode,
	type BinaryNodeAttributes,
	getBinaryFilteredBizBot,
	getBinaryFilteredButtons,
	getBinaryNodeChild,
	getBinaryNodeChildren,
	isJidGroup,
	isJidNewsletter,
	isJidUser,
	jidDecode,
	jidEncode,
	jidNormalizedUser,
	type JidWithDevice,
	S_WHATSAPP_NET,
	STORIES_JID
} from '../WABinary'
import { USyncQuery, USyncUser } from '../WAUSync'
import { makeGroupsSocket } from './groups'
import type { NewsletterSocket } from './newsletter'
import { makeNewsletterSocket } from './newsletter'

export const makeMessagesSocket = (config: SocketConfig) => {
	const {
		logger,
		linkPreviewImageThumbnailWidth,
		generateHighQualityLinkPreview,
		options: axiosOptions,
		patchMessageBeforeSending,
		cachedGroupMetadata,
		messageCacheConfig
	} = config
	const sock: NewsletterSocket = makeNewsletterSocket(makeGroupsSocket(config))
	const {
		ev,
		authState,
		processingMutex,
		signalRepository,
		upsertMessage,
		query,
		fetchPrivacySettings,
		sendNode,
		groupMetadata,
		groupToggleEphemeral,
	} = sock

	// Initialize built-in message cache (replaces external getMessage)
	const messageCache = new MessageCache(logger, messageCacheConfig)

	// Cleanup cache on socket destruction
	const originalDestroy = (sock as any).destroy
	if (originalDestroy) {
		(sock as any).destroy = () => {
			messageCache.destroy()
			return originalDestroy.call(sock)
		}
	}

	const userDevicesCache =
		config.userDevicesCache ||
		new NodeCache({
			stdTTL: DEFAULT_CACHE_TTLS.USER_DEVICES, // 5 minutes
			useClones: false
		})

	// Prevent race conditions in Signal session encryption by user
	const encryptionMutex = makeKeyedMutex()

	let mediaConn: Promise<MediaConnInfo>
	const refreshMediaConn = async (forceGet = false) => {
		const media = await mediaConn
		if (!media || forceGet || new Date().getTime() - media.fetchDate.getTime() > media.ttl * 1000) {
			mediaConn = (async () => {
				const result = await query({
					tag: 'iq',
					attrs: {
						type: 'set',
						xmlns: 'w:m',
						to: S_WHATSAPP_NET
					},
					content: [{ tag: 'media_conn', attrs: {} }]
				})
				const mediaConnNode = getBinaryNodeChild(result, 'media_conn')!
				const node: MediaConnInfo = {
					hosts: getBinaryNodeChildren(mediaConnNode, 'host').map(({ attrs }) => ({
						hostname: attrs.hostname!,
						maxContentLengthBytes: +attrs.maxContentLengthBytes!
					})),
					auth: mediaConnNode.attrs.auth!,
					ttl: +mediaConnNode.attrs.ttl!,
					fetchDate: new Date()
				}
				logger.debug('fetched media conn')
				return node
			})()
		}

		return mediaConn
	}

	/**
	 * generic send receipt function
	 * used for receipts of phone call, read, delivery etc.
	 * */
	const sendReceipt = async (
		jid: string,
		participant: string | undefined,
		messageIds: string[],
		type: MessageReceiptType
	) => {
		if (!messageIds || messageIds.length === 0) {
			throw new Boom('missing ids in receipt')
		}

		const node: BinaryNode = {
			tag: 'receipt',
			attrs: {
				id: messageIds[0]!
			}
		}
		const isReadReceipt = type === 'read' || type === 'read-self'
		if (isReadReceipt) {
			node.attrs.t = unixTimestampSeconds().toString()
		}

		if (type === 'sender' && isJidUser(jid)) {
			node.attrs.recipient = jid
			node.attrs.to = participant!
		} else {
			node.attrs.to = jid
			if (participant) {
				node.attrs.participant = participant
			}
		}

		if (type) {
			node.attrs.type = type
		}

		const remainingMessageIds = messageIds.slice(1)
		if (remainingMessageIds.length) {
			node.content = [
				{
					tag: 'list',
					attrs: {},
					content: remainingMessageIds.map(id => ({
						tag: 'item',
						attrs: { id }
					}))
				}
			]
		}

		logger.debug({ attrs: node.attrs, messageIds }, 'sending receipt for messages')
		await sendNode(node)
	}

	/** Correctly bulk send receipts to multiple chats, participants */
	const sendReceipts = async (keys: WAMessageKey[], type: MessageReceiptType) => {
		const recps = aggregateMessageKeysNotFromMe(keys)
		for (const { jid, participant, messageIds } of recps) {
			await sendReceipt(jid, participant, messageIds, type)
		}
	}

	/** Bulk read messages. Keys can be from different chats & participants */
	const readMessages = async (keys: WAMessageKey[]) => {
		const privacySettings = await fetchPrivacySettings()
		// based on privacy settings, we have to change the read type
		const readType = privacySettings.readreceipts === 'all' ? 'read' : 'read-self'
		await sendReceipts(keys, readType)
	}

	/** Device info with wire JID format for envelope addressing */
	type DeviceWithWireJid = JidWithDevice & {
		wireJid: string // The exact JID format that should be used in wire protocol (envelope addressing)
	}

	/** Fetch all the devices we've to send a message to */
	const getUSyncDevices = async (jids: string[], useCache: boolean, ignoreZeroDevices: boolean, conversationContext?: 'pn' | 'lid'): Promise<DeviceWithWireJid[]> => {
		const deviceResults: DeviceWithWireJid[] = []

		// DEBUG: Log input JIDs to understand what's being passed
		logger.debug({ jids, useCache, ignoreZeroDevices, conversationContext }, '🔍 getUSyncDevices called with JIDs')

		if (!useCache) {
			logger.debug('not using cache for devices')
		}

		const toFetch: string[] = []
		jids = Array.from(new Set(jids))
		
		// LID CENTRALIZATION: Remove PN duplicates when LID versions exist
		// Always prefer LID version to maintain single encryption layer
		const lidUsers = new Set<string>()
		const filteredJids: string[] = []
		
		// First pass: collect all LID users
		for (const jid of jids) {
			if (jid.includes('@lid')) {
				const user = jidDecode(jid)?.user
				if (user) {
					lidUsers.add(user)
				}
			}
		}
		
		// Second pass: filter out PN versions if LID exists
		for (const jid of jids) {
			if (jid.includes('@s.whatsapp.net')) {
				const user = jidDecode(jid)?.user
				if (user && lidUsers.has(user)) {
					logger.debug({ jid, lidUser: user }, '🚫 Skipping PN version - LID version exists')
					continue // Skip PN version when LID exists
				}
			}
			filteredJids.push(jid)
		}
		
		jids = filteredJids
		logger.debug({ originalCount: Array.from(new Set(jids)).length, filteredCount: jids.length, filteredJids: jids }, '✅ Filtered JIDs to remove PN/LID duplicates')

		for (let jid of jids) {
			const decoded = jidDecode(jid)
			const user = decoded?.user
			const device = decoded?.device
			
			// CRITICAL FIX: Handle explicit device JIDs vs user JIDs
			// Explicit device JIDs (like 102765716062358:58@lid) should be used as-is
			// User JIDs (like 102765716062358@lid) need device enumeration
			const isExplicitDevice = typeof device === 'number' && device >= 0
			
			if (jid.includes('@lid')) {
				logger.debug({ jid, isExplicitDevice, device }, 'Processing LID address')
				
				if (isExplicitDevice) {
					// This is an explicit device JID - use as-is, no enumeration needed
					logger.debug({ jid }, '✅ Using explicit LID device JID as-is')
					deviceResults.push({ 
						user: user!, 
						device: device!,
						wireJid: jid // Preserve exact JID format
					})
				} else {
					// This is a user JID - add to enumeration list for device discovery
					logger.debug({ jid }, '📋 Adding LID user JID to enumeration list')
					toFetch.push(jid)
				}
				continue // Skip normal PN-specific processing for LID addresses
			}
			
			// Normal PN processing - WHATSMEOW PATTERN: Check for LID mapping first (LID priority)
			jid = jidNormalizedUser(jid)
			
			// ADDRESSING MODE CONSISTENCY: Check if this is our own device
			const currentUserJid = jidNormalizedUser(authState.creds.me!.id)
			const isOwnDevice = jidNormalizedUser(jid) === currentUserJid
			
			// Check if this is an explicit device JID (needed for both own and recipient devices)
			const originalDecoded = jidDecode(jid)
			const originalDevice = originalDecoded?.device
			const isExplicitPNDevice = typeof originalDevice === 'number' && originalDevice >= 0
			
			// OWN DEVICE LID MIGRATION: Apply LID migration to own devices too for single encryption layer
			if (isOwnDevice) {
				try {
					const lidMapping = signalRepository.getLIDMappingStore()
					const ownLidForPN = await lidMapping.getLIDForPN(jid)
					
					if (ownLidForPN && ownLidForPN.includes('@lid')) {
						// Found LID mapping for own device - migrate to LID-only encryption
						logger.info({ originalPN: jid, ownLidAddress: ownLidForPN }, '📱 Own device LID mapping found - switching to LID-only encryption')
						
						// Migrate own device sessions to LID
						try {
							await signalRepository.migrateSession(jid, ownLidForPN)
							logger.info({ from: jid, to: ownLidForPN }, '🔄 Migrated own device sessions from PN to LID (single encryption layer)')
						} catch (migrationError) {
							logger.warn({ jid, ownLidForPN, error: migrationError }, 'Failed to migrate own device sessions')
						}
						
						// Process as LID device - skip PN processing completely
						const lidDecoded = jidDecode(ownLidForPN)
						const ownLidUser = lidDecoded?.user
						const actualDeviceId = originalDecoded?.device || 0
						
						if (ownLidUser) {
							// CRITICAL: Keep PN wire identity but use LID for encryption sessions
							const meId = authState.creds.me!.id
							const originalPnUser = jidDecode(meId)!.user
							const wireJid = jidEncode(originalPnUser, 's.whatsapp.net', actualDeviceId)
							
							deviceResults.push({
								user: originalPnUser, // PN user for wire consistency
								device: actualDeviceId,
								wireJid: wireJid // PN wire JID for envelope (encryption will migrate to LID automatically)
							})
							
							logger.info({ 
								wireJid: wireJid,
								reason: 'pn_wire_unified_encryption'
							}, '✅ Added own device: PN wire JID with unified encryption layer')
							continue // Skip PN processing for own device
						}
					}
				} catch (error) {
					logger.debug({ jid, error }, 'Failed to check own device LID mapping')
				}
			}
			
			if (isExplicitPNDevice) {
				// This is an explicit PN device JID - use as-is, no enumeration needed
				logger.debug({ jid }, '✅ Using explicit PN device JID as-is')
				deviceResults.push({ 
					user: user!, 
					device: originalDevice!,
					wireJid: jid // Preserve exact JID format
				})
				continue // Skip enumeration for explicit device JIDs
			}
			
			// BULK LID MIGRATION: Check for LID mapping for both recipient and own devices
			// The unified encryption layer will handle the actual migration during encryption
			try {
				const lidMapping = signalRepository.getLIDMappingStore()
				const lidForPN = await lidMapping.getLIDForPN(jid)
				
				if (lidForPN && lidForPN.includes('@lid')) {
					// Found LID mapping - will be migrated in bulk during USyncQuery
					// For now, just note that this user has LID mapping available
					logger.debug({ originalPN: jid, lidAddress: lidForPN, isOwnDevice }, '📋 LID mapping found - will be handled in bulk migration')
				}
			} catch (error) {
				logger.debug({ jid, error }, 'Failed to check LID mapping during device enumeration')
			}
			
			// Continue with normal PN processing if no LID mapping found
			logger.debug({ jid, user }, '📞 Processing PN address without LID mapping')
			
			if (useCache) {
				const devices = userDevicesCache.get(user!) as JidWithDevice[]
				if (devices) {
					// Convert cached devices to wire format - use LID if original JID was LID
					const isLidJid = jid.includes('@lid')
					const devicesWithWire = devices.map(d => ({
						...d,
						wireJid: isLidJid 
							? jidEncode(d.user, 'lid', d.device)
							: jidEncode(d.user, 's.whatsapp.net', d.device)
					}))
					deviceResults.push(...devicesWithWire)

					logger.debug({ user, deviceCount: devices.length, usedLid: isLidJid }, '✅ Found cached devices')
				} else {
					logger.debug({ jid, user }, '🔍 No cached devices, adding to fetch list')
					toFetch.push(jid)
				}
			} else {
				logger.debug({ jid, user }, '🔍 Cache disabled, adding to fetch list')
				toFetch.push(jid)
			}
		}

		if (!toFetch.length) {
			logger.debug({ deviceResultsCount: deviceResults.length }, '✅ No JIDs to fetch, returning existing devices')
			return deviceResults
		}

		logger.info({ toFetch, fetchCount: toFetch.length }, '🔍 Executing USyncQuery for device enumeration')
		
		// Track which users are LID format for later wireJid assignment
		const requestedLidUsers = new Set<string>()
		for (const jid of toFetch) {
			if (jid.includes('@lid')) {
				const user = jidDecode(jid)?.user
				if (user) requestedLidUsers.add(user)
			}
		}
		
		const query = new USyncQuery().withContext('message').withDeviceProtocol()

		for (const jid of toFetch) {
			query.withUser(new USyncUser().withId(jid))
			logger.debug({ jid }, '📋 Added JID to USyncQuery')
		}

		const result = await sock.executeUSyncQuery(query)
		logger.debug({ hasResult: !!result, resultList: !!result?.list }, '📊 USyncQuery completed')

		if (result) {
			const extracted = extractDeviceJids(result?.list, authState.creds.me!.id, ignoreZeroDevices)
			logger.info({ extractedCount: extracted.length, extracted: extracted.map(e => ({ user: e.user, device: e.device })) }, '📱 Extracted devices from USyncQuery')
			
			const deviceMap: { [_: string]: JidWithDevice[] } = {}

			// First, group all devices by user
			for (const item of extracted) {
				deviceMap[item.user] = deviceMap[item.user] || []
				deviceMap[item.user]?.push(item)
			}

			// Process each user's devices - use LID format if originally requested as LID
			for (const [user, userDevices] of Object.entries(deviceMap)) {
				const isLidUser = requestedLidUsers.has(user)
				
				// Process all devices for this user
				for (const item of userDevices) {
					const finalWireJid = isLidUser
						? jidEncode(user, 'lid', item.device)
						: jidEncode(item.user, 's.whatsapp.net', item.device)

					deviceResults.push({
						...item,
						wireJid: finalWireJid
					})
					
					logger.debug({ 
						user: item.user, 
						device: item.device, 
						finalWireJid,
						usedLid: isLidUser 
					}, '📱 Processed device with direct addressing')
				}
			}

			// Cache the results
			for (const key in deviceMap) {
				userDevicesCache.set(key, deviceMap[key]!)
				logger.debug({ user: key, deviceCount: deviceMap[key]!.length }, '💾 Cached devices for user')
			}
		} else {
			logger.warn({ toFetch }, '❌ USyncQuery returned no results')
		}

		return deviceResults
	}

	// Simplified session recreation logic using signalRepository
	const shouldRecreateSessionForRetry = async (retryCount: number, participant: string): Promise<{ recreate: boolean, reason: string }> => {
		// Check if we have a session for this participant
		const sessionKey = signalRepository.jidToSignalProtocolAddress(participant)
		const participantSessions = await authState.keys.get('session', [sessionKey])
		const hasSession = Object.keys(participantSessions).length > 0 && participantSessions[sessionKey]
		
		if (!hasSession) {
			return { recreate: true, reason: "no session exists with participant" }
		}
		
		// Use signalRepository's recreation logic (already has rate limiting)
		const result = signalRepository.shouldRecreateSession(participant, retryCount)
		return { recreate: result.shouldRecreate, reason: result.reason }
	}

	const assertSessions = async (jids: string[], force: boolean, retryContext?: { retryCount: number, participant: string }) => {
		let didFetchNewSession = false
		let jidsRequiringFetch: string[] = []
		
		// CRITICAL FIX: Apply same LID/PN deduplication as in getUSyncDevices
		// Remove PN duplicates when LID versions exist
		const lidUsers = new Set<string>()
		const filteredJids: string[] = []
		
		// First pass: collect all LID users
		for (const jid of jids) {
			if (jid.includes('@lid')) {
				const user = jidDecode(jid)?.user
				if (user) {
					lidUsers.add(user)
				}
			}
		}
		
		// Second pass: filter out PN versions if LID exists
		for (const jid of jids) {
			if (jid.includes('@s.whatsapp.net')) {
				const user = jidDecode(jid)?.user
				if (user && lidUsers.has(user)) {
					logger.debug({ jid, lidUser: user }, '🚫 assertSessions: Skipping PN version - LID version exists')
					continue // Skip PN version when LID exists
				}
			}
			filteredJids.push(jid)
		}
		
		jids = filteredJids
		logger.debug({ originalJids: jids.length, filteredJids: jids.length, jids }, '✅ assertSessions: Filtered JIDs to remove PN/LID duplicates')
		
		if (force) {
			// WHATSMEOW PATTERN: Enhanced force logic for session recreation
			if (retryContext) {
				// Check if we should recreate sessions based on whatsmeow logic
				const { retryCount, participant } = retryContext
				const shouldRecreate = await shouldRecreateSessionForRetry(retryCount, participant)
				
				if (shouldRecreate.recreate) {
					logger.info({ participant, retryCount, reason: shouldRecreate.reason }, 'Recreating session per whatsmeow pattern')
					
					// CRITICAL: Delete existing broken sessions first (whatsmeow pattern)
					const sessionsToDelete: { [key: string]: null } = {}
					const sessionKeysToRecreate: string[] = []
					for (const jid of jids) {
						const sessionKey = signalRepository.jidToSignalProtocolAddress(jid)
						sessionsToDelete[sessionKey] = null
						sessionKeysToRecreate.push(sessionKey)
					}
					await authState.keys.set({ 'session': sessionsToDelete })
					
			jidsRequiringFetch = jids
				} else {
					logger.debug({ participant, retryCount, reason: shouldRecreate.reason }, 'Using existing sessions')
					// Still check which sessions are missing (with LID migration check)
					const lidMapping = signalRepository.getLIDMappingStore()
					const addrs = jids.map(jid => signalRepository.jidToSignalProtocolAddress(jid))
					const sessions = await authState.keys.get('session', addrs)
					
					for (const jid of jids) {
						const signalId = signalRepository.jidToSignalProtocolAddress(jid)
						let hasSession = !!sessions[signalId]
						
						// Check for migrated LID session if PN session missing
						if (!hasSession && jid.includes('@s.whatsapp.net')) {
							try {
								const lidForPN = await lidMapping.getLIDForPN(jid)
								if (lidForPN && lidForPN.includes('@lid')) {
									const lidSignalId = signalRepository.jidToSignalProtocolAddress(lidForPN)
									const lidSessions = await authState.keys.get('session', [lidSignalId])
									hasSession = !!lidSessions[lidSignalId]
									
									if (hasSession) {
										logger.debug({ jid, lidForPN }, 'Found migrated LID session during retry, skipping PN fetch')
									}
								}
							} catch (err: any) {
								logger.warn({ jid, err: err.message }, 'Failed to check LID mapping during session assertion')
							}
						}
						
						// CRITICAL FIX: Handle LID addresses properly - don't fallback to PN fetching
						if (!hasSession && jid.includes('@lid')) {
							// For LID addresses, we should create new LID sessions, not fallback to PN
							logger.debug({ jid }, 'No LID session found, will create new LID session')
							jidsRequiringFetch.push(jid)
						} else if (!hasSession && !jid.includes('@lid')) {
							// Only add PN addresses to fetch list
							jidsRequiringFetch.push(jid)
						}
					}
				}
			} else {
				// Standard force behavior - fetch for all
				jidsRequiringFetch = jids
			}
		} else {
			// BULK MIGRATION APPROACH: Group devices by user and check for LID mappings
			const lidMapping = signalRepository.getLIDMappingStore()
			const addrs = jids.map(jid => signalRepository.jidToSignalProtocolAddress(jid))
			const sessions = await authState.keys.get('session', addrs)
			
			// Group JIDs by user for bulk migration
			const userGroups = new Map<string, string[]>()
			for (const jid of jids) {
				const user = jidNormalizedUser(jid)
				if (!userGroups.has(user)) {
					userGroups.set(user, [])
				}
				userGroups.get(user)!.push(jid)
			}
			
			// Process each user group for potential bulk LID migration
			for (const [user, userJids] of userGroups) {
				let shouldMigrateUser = false
				let lidForPN: string | undefined
				
				// Check if this user has LID mapping (once per user)
				if (userJids.some(jid => jid.includes('@s.whatsapp.net'))) {
					try {
						const mapping = await lidMapping.getLIDForPN(user)
						if (mapping && mapping.includes('@lid')) {
							lidForPN = mapping
							shouldMigrateUser = true
							logger.debug({ user, lidForPN, deviceCount: userJids.length }, '📋 User has LID mapping - preparing bulk migration')
						}
					} catch (error) {
						logger.debug({ user, error }, 'Failed to check LID mapping for user')
					}
				}
				
				// Bulk migrate all devices for this user if LID mapping exists
				if (shouldMigrateUser && lidForPN) {
					try {
						await signalRepository.migrateSession(user, lidForPN)
						logger.info({ 
							user, 
							lidMapping: lidForPN, 
							deviceCount: userJids.length,
							devices: userJids
						}, '🔄 BULK MIGRATION: All user sessions migrated to LID in assertSessions')
						
						// Delete all PN sessions for this user in parallel
						const pnJidsToDelete = userJids.filter(jid => jid.includes('@s.whatsapp.net'))
						const deletionPromises = pnJidsToDelete.map(async (jid) => {
							try {
								await signalRepository.deleteSession(jid)
								logger.debug({ deletedPNSession: jid }, '🗑️ Deleted PN session in bulk assertSessions migration')
							} catch (deleteError) {
								logger.warn({ jid, error: deleteError }, 'Failed to delete PN session in bulk assertSessions migration')
							}
						})
						await Promise.all(deletionPromises)
						
					} catch (migrationError) {
						logger.warn({ user, lidForPN, error: migrationError }, 'Failed to bulk migrate user sessions in assertSessions')
						shouldMigrateUser = false
					}
				}
				
				// Now check which sessions need to be fetched for this user
				for (const jid of userJids) {
					const signalId = signalRepository.jidToSignalProtocolAddress(jid)
					let hasSession = !!sessions[signalId]
					let jidToFetch = jid
					
					// If we migrated this user to LID, check LID sessions instead
					if (shouldMigrateUser && lidForPN && jid.includes('@s.whatsapp.net')) {
						const originalDecoded = jidDecode(jid)
						const deviceId = originalDecoded?.device || 0
						const lidDecoded = jidDecode(lidForPN)
						const lidWithDevice = jidEncode(lidDecoded?.user!, 'lid', deviceId)
						
						// Check if LID session exists
						const lidSignalId = signalRepository.jidToSignalProtocolAddress(lidWithDevice)
						const lidSessions = await authState.keys.get('session', [lidSignalId])
						hasSession = !!lidSessions[lidSignalId]
						jidToFetch = lidWithDevice
						
						if (hasSession) {
							logger.debug({ originalJid: jid, lidJid: lidWithDevice }, '✅ Found bulk-migrated LID session')
						}
					}
					
					// Add to fetch list if no session exists
					if (!hasSession) {
						jidsRequiringFetch.push(jidToFetch)
						logger.debug({ jid: jidToFetch, originalJid: jid !== jidToFetch ? jid : undefined }, 'Adding to session fetch list')
					}
				}
			}
		}

		if (jidsRequiringFetch.length) {
			logger.debug({ jidsRequiringFetch }, 'fetching sessions')
			
			// DEBUG: Check if there are PN versions of LID users being fetched
			const lidUsersBeingFetched = new Set<string>()
			const pnUsersBeingFetched = new Set<string>()
			
			for (const jid of jidsRequiringFetch) {
				const user = jidDecode(jid)?.user
				if (user) {
					if (jid.includes('@lid')) {
						lidUsersBeingFetched.add(user)
					} else if (jid.includes('@s.whatsapp.net')) {
						pnUsersBeingFetched.add(user)
					}
				}
			}
			
			// Find overlaps
			const overlapping = Array.from(pnUsersBeingFetched).filter(user => lidUsersBeingFetched.has(user))
			if (overlapping.length > 0) {
				logger.warn({ overlapping, lidUsersBeingFetched: Array.from(lidUsersBeingFetched), pnUsersBeingFetched: Array.from(pnUsersBeingFetched) }, '🚨 PROBLEM: Fetching both LID and PN sessions for same users')
			}
			const result = await query({
				tag: 'iq',
				attrs: {
					xmlns: 'encrypt',
					type: 'get',
					to: S_WHATSAPP_NET
				},
				content: [
					{
						tag: 'key',
						attrs: {},
						content: jidsRequiringFetch.map(jid => ({
							tag: 'user',
							attrs: { jid }
						}))
					}
				]
			})
			await parseAndInjectE2ESessions(result, signalRepository)

			didFetchNewSession = true
		}

		return didFetchNewSession
	}

	const sendPeerDataOperationMessage = async (
		pdoMessage: proto.Message.IPeerDataOperationRequestMessage
	): Promise<string> => {
		//TODO: for later, abstract the logic to send a Peer Message instead of just PDO - useful for App State Key Resync with phone
		if (!authState.creds.me?.id) {
			throw new Boom('Not authenticated')
		}

		const protocolMessage: proto.IMessage = {
			protocolMessage: {
				peerDataOperationRequestMessage: pdoMessage,
				type: proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE
			}
		}

		const meJid = jidNormalizedUser(authState.creds.me.id)

		const msgId = await relayMessage(meJid, protocolMessage, {
			additionalAttributes: {
				category: 'peer',

				push_priority: 'high_force'
			}
		})

		return msgId
	}

	const createParticipantNodes = async (
		jids: string[], 
		message: proto.IMessage, 
		extraAttrs?: BinaryNode['attrs'],
		// DSM support for own devices
		dsmMessage?: proto.IMessage
	) => {
		let patched = await patchMessageBeforeSending(message, jids)
		if (!Array.isArray(patched)) {
			patched = jids ? jids.map(jid => ({ recipientJid: jid, ...patched })) : [patched]
		}

		let shouldIncludeDeviceIdentity = false
		const meId = authState.creds.me!.id
		const meLid = authState.creds.me?.lid
		const meLidUser = meLid ? jidDecode(meLid)?.user : null

		// RACE CONDITION FIX: Group devices by user to prevent Signal session corruption
		// Encrypt to all devices of same user sequentially, but different users in parallel
		const devicesByUser = new Map<string, Array<{ recipientJid: string, patchedMessage: any }>>()
		
		for (const patchedMessageWithJid of patched) {
			const { recipientJid: wireJid, ...patchedMessage } = patchedMessageWithJid
			if (!wireJid) continue
			
			// Extract user from JID for grouping
			const decoded = jidDecode(wireJid)
			const user = decoded?.user
			if (!user) continue
			
			if (!devicesByUser.has(user)) {
				devicesByUser.set(user, [])
			}
			devicesByUser.get(user)!.push({ recipientJid: wireJid, patchedMessage })
		}

		// Process each user's devices sequentially, but different users in parallel
		const userEncryptionPromises = Array.from(devicesByUser.entries()).map(([user, userDevices]) => 
			encryptionMutex.mutex(user, async () => {
				logger.debug({ user, deviceCount: userDevices.length }, '🔒 Acquiring encryption lock for user devices')
				
				const userNodes: BinaryNode[] = []
				
				// Encrypt to this user's devices sequentially to prevent session corruption
				for (const { recipientJid: wireJid, patchedMessage } of userDevices) {
					// DSM logic: Use DSM for own other devices (following whatsmeow implementation)
					let messageToEncrypt = patchedMessage
					if (dsmMessage) {
						const { user: targetUser } = jidDecode(wireJid)!
						const { user: ownPnUser } = jidDecode(meId)!
						const ownLidUser = meLidUser
						
						// Check if this is our device (same user, different device)
						const isOwnUser = targetUser === ownPnUser || (ownLidUser && targetUser === ownLidUser)
						
						// Exclude exact sender device (whatsmeow: if jid == ownJID || jid == ownLID { continue })
						const isExactSenderDevice = wireJid === meId || (authState.creds.me?.lid && wireJid === authState.creds.me.lid)
						
						if (isOwnUser && !isExactSenderDevice) {
							messageToEncrypt = dsmMessage
							logger.debug({ wireJid, targetUser }, '📱 Using DSM for own device')
						}
					}

					const bytes = encodeWAMessage(messageToEncrypt)
					
					// UNIFIED ENCRYPTION LAYER: Always use migrated LID session when available
					// Keep wire JID for envelope addressing, but simplify encryption to LID-first approach
					let encryptionJid = wireJid
					
					// Check if we should migrate this device to LID for encryption
					const recipientUser = jidNormalizedUser(wireJid)
					const ownPnUser = jidNormalizedUser(meId)
					const isOwnDevice = recipientUser === ownPnUser
					
					// For ALL devices (own and recipient), check for LID migration for unified encryption layer
					if (wireJid.includes('@s.whatsapp.net')) {
						try {
							const lidMapping = signalRepository.getLIDMappingStore()
							const lidForPN = await lidMapping.getLIDForPN(recipientUser)
							
							if (lidForPN && lidForPN.includes('@lid')) {
								// Preserve device ID from original wire JID
								const wireDecoded = jidDecode(wireJid)
								const deviceId = wireDecoded?.device || 0
								const lidDecoded = jidDecode(lidForPN)
								const lidWithDevice = jidEncode(lidDecoded?.user!, 'lid', deviceId)
								
								// Migrate session to LID for unified encryption layer
								try {
									await signalRepository.migrateSession(recipientUser, lidForPN)
									logger.info({ user: recipientUser, isOwnDevice, lidMapping: lidForPN, deviceId }, '🔄 Migrated to LID encryption (unified layer)')
									
									// Delete PN session - we only want LID sessions for encryption
									try {
										await signalRepository.deleteSession(wireJid)
										logger.debug({ deletedPNSession: wireJid, usingLIDSession: lidWithDevice }, '🗑️ Deleted PN session - unified LID encryption')
									} catch (deleteError) {
										logger.warn({ wireJid, lidWithDevice, error: deleteError }, 'Failed to delete PN session')
									}
									
									// Always use LID for encryption, keep wire JID for addressing
									encryptionJid = lidWithDevice
									logger.debug({ wireJid, encryptionJid, isOwnDevice }, '🔐 Unified LID encryption layer')
									
								} catch (migrationError) {
									logger.warn({ user: recipientUser, lidForPN, error: migrationError }, 'Failed to migrate to LID - using PN encryption')
								}
							}
						} catch (error) {
							logger.debug({ wireJid, error }, 'Failed to check LID mapping')
						}
					}
					
					// ENCRYPT: Use the determined encryption identity (prefers migrated LID)
					const { type, ciphertext } = await signalRepository.encryptMessage({ 
						jid: encryptionJid,  // Unified encryption layer (LID when available)
						data: bytes
					})
					
					if (type === 'pkmsg') {
						shouldIncludeDeviceIdentity = true
					}

					const node: BinaryNode = {
						tag: 'to',
						attrs: { jid: wireJid },  // Always use original wire identity in envelope
						content: [
							{
								tag: 'enc',
								attrs: {
									v: '2',
									type,
									...(extraAttrs || {})
								},
								content: ciphertext
							}
						]
					}
					userNodes.push(node)
				}
				
				logger.debug({ user, nodesCreated: userNodes.length }, '🔓 Releasing encryption lock for user devices')
				return userNodes
			})
		)

		// Wait for all users to complete (users are processed in parallel)
		const userNodesArrays = await Promise.all(userEncryptionPromises)
		const nodes = userNodesArrays.flat()

		logger.debug({ 
			totalDevices: jids.length, 
			uniqueUsers: devicesByUser.size,
			nodesCreated: nodes.length
		}, '✅ Multi-user encryption completed with race condition protection')

		return { nodes, shouldIncludeDeviceIdentity }
	}

	const relayMessage = async (
		jid: string,
		message: proto.IMessage,
		{
			messageId: msgId,
			participant,
			additionalAttributes,
			additionalNodes,
			useUserDevicesCache,
			useCachedGroupMetadata,
			statusJidList,
			targetDevices
		}: MessageRelayOptions
	) => {
		let meId = authState.creds.me!.id
		let meLid = authState.creds.me?.lid

		// ADDRESSING CONSISTENCY: Keep envelope addressing as user provided, handle LID migration in encryption
		// When sending to @s.whatsapp.net -> use authState.creds.me!.id for own addressing 
		// When sending to @lid -> use authState.creds.me.lid for own addressing
		// Encryption layer will handle LID session migration automatically

		let shouldIncludeDeviceIdentity = false

		let { user, server } = jidDecode(jid)!
		const statusJid = 'status@broadcast'
		const isGroup = server === 'g.us'
		const isStatus = jid === statusJid
		let isLid = server === 'lid'
		const isNewsletter = server === 'newsletter'
		
		// Keep user's original JID choice for envelope addressing
		let finalJid = jid
		
		// ADDRESSING CONSISTENCY: Match own identity to conversation context
		let ownId = meId
		if (isLid && meLid) {
			ownId = meLid
			logger.debug({ to: jid, ownId }, 'Using LID identity for @lid conversation')
		} else {
			logger.debug({ to: jid, ownId }, 'Using PN identity for @s.whatsapp.net conversation')
		}

		msgId = msgId || generateMessageIDV2(sock.user?.id)
		useUserDevicesCache = useUserDevicesCache !== false
		useCachedGroupMetadata = useCachedGroupMetadata !== false && !isStatus

		const participants: BinaryNode[] = []
		const destinationJid = !isStatus ? finalJid : statusJid
		
		const binaryNodeContent: BinaryNode[] = []
		const devices: DeviceWithWireJid[] = []

		// DSM is only created for 1:1 chats (following whatsmeow implementation)
		const meMsg: proto.IMessage | undefined = (!isGroup && !isStatus) ? {
			deviceSentMessage: {
				destinationJid,
				message
			}
		} : undefined

		const extraAttrs: BinaryNodeAttributes = {}

		if (participant) {
			// when the retry request is not for a group
			// only send to the specific device that asked for a retry
			// otherwise the message is sent out to every device that should be a recipient
			if (!isGroup && !isStatus) {
				additionalAttributes = { ...additionalAttributes, device_fanout: 'false' }
			}

			const { user, device } = jidDecode(participant.jid)!
			devices.push({ 
				user, 
				device,
				wireJid: participant.jid // Use the participant JID as wire JID
			})
		}

		await authState.keys.transaction(async () => {
			let didPushAdditional = false
			const messages = normalizeMessageContent(message)
			const buttonType = messages ? getButtonType(messages) : undefined

			const mediaType = getMediaType(message)
			if (mediaType) {
				extraAttrs['mediatype'] = mediaType
			}

			if (
				messages?.pinInChatMessage ||
				messages?.keepInChatMessage ||
				message.reactionMessage ||
				message.protocolMessage?.editedMessage
			) {
				extraAttrs['decrypt-fail'] = 'hide'
			}

			if (messages?.interactiveResponseMessage?.nativeFlowResponseMessage) {
				extraAttrs['native_flow_name'] = messages?.interactiveResponseMessage?.nativeFlowResponseMessage.name || ''
			}

			if (isNewsletter) {
				// Patch message if needed, then encode as plaintext
				const patched = patchMessageBeforeSending ? await patchMessageBeforeSending(message, []) : message
				const bytes = encodeNewsletterMessage(patched as proto.IMessage)
				binaryNodeContent.push({
					tag: 'plaintext',
					attrs: {},
					content: bytes
				})

				const stanza: BinaryNode = {
					tag: 'message',
					attrs: {
						to: jid,
						id: msgId,
						type: getMessageType(message),
						...(additionalAttributes || {})
					},
					content: binaryNodeContent
				}
				logger.debug({ msgId }, `sending newsletter message to ${jid}`)
				await sendNode(stanza)
				return
			}

			if (isGroup || isStatus) {
				const [groupData, senderKeyMap] = await Promise.all([
					(async () => {
						let groupData = useCachedGroupMetadata && cachedGroupMetadata ? await cachedGroupMetadata(jid) : undefined
						if (groupData && Array.isArray(groupData?.participants)) {
							logger.trace({ jid, participants: groupData.participants.length }, 'using cached group metadata')
						} else if (!isStatus) {
							groupData = await groupMetadata(jid)
						}

						return groupData
					})(),
					(async () => {
						if (!participant && !isStatus) {
							const result = await authState.keys.get('sender-key-memory', [jid])
							return result[jid] || {}
						}

						return {}
					})()
				])

				if (!participant) {
					const participantsList = groupData && !isStatus ? groupData.participants.map(p => p.id) : []
					if (isStatus && statusJidList) {
						participantsList.push(...statusJidList)
					}

					if (!isStatus) {
						// ADDRESSING MODE: Use group's addressing mode if set, otherwise match conversation context
						const groupAddressingMode = groupData?.addressingMode || (isLid ? 'lid' : 'pn')
						additionalAttributes = {
							...additionalAttributes,
							addressing_mode: groupAddressingMode
						}
					}

					// Use group's addressing mode or conversation context for device enumeration
					const conversationMode = groupData?.addressingMode === 'lid' ? 'lid' : (isLid ? 'lid' : 'pn')
					logger.debug({ 
						group: jid,
						participantCount: participantsList.length,
						conversationMode,
						groupAddressingMode: groupData?.addressingMode
					}, '📡 Enumerating group participant devices')
					
					const additionalDevices = await getUSyncDevices(participantsList, !!useUserDevicesCache, false, conversationMode)
					devices.push(...additionalDevices)
					
					logger.debug({ 
						group: jid,
						enumeratedDevices: additionalDevices.length,
						totalDevices: devices.length,
						deviceSample: additionalDevices.slice(0, 3).map(d => ({ user: d.user, device: d.device, wireJid: d.wireJid }))
					}, '✅ Group device enumeration complete')
				}

				const patched = await patchMessageBeforeSending(message)

				if (Array.isArray(patched)) {
					throw new Boom('Per-jid patching is not supported in groups')
				}

				const bytes = encodeWAMessage(patched)

				// GROUP SENDER IDENTITY: Use LID identity for LID groups, PN identity for PN groups
				// This should match the group's addressing mode and conversation context
				const groupAddressingMode = groupData?.addressingMode || (isLid ? 'lid' : 'pn')
				const groupSenderIdentity = (groupAddressingMode === 'lid' && meLid) ? meLid : meId
				
				logger.debug({ 
					group: destinationJid,
					groupAddressingMode,
					groupSenderIdentity,
					participantCount: devices.length
				}, '🔑 Group encryption with unified addressing')
				
				const { ciphertext, senderKeyDistributionMessage } = await signalRepository.encryptGroupMessage({
					group: destinationJid,
					data: bytes,
					meId: groupSenderIdentity
				})

				const senderKeyJids: string[] = []
				// ensure a connection is established with every device
				for (const device of devices) {
					// CRITICAL FIX: Use wireJid from device enumeration instead of rebuilding
					// This preserves the LID migration results from getUSyncDevices
					const deviceJid = device.wireJid
					const hasKey = !!senderKeyMap[deviceJid]
					if (!hasKey || !!participant) {
						senderKeyJids.push(deviceJid)
						// store that this person has had the sender keys sent to them
						senderKeyMap[deviceJid] = true
					}
				}

				// if there are some participants with whom the session has not been established
				// if there are, we re-send the senderkey
				if (senderKeyJids.length) {
					logger.debug({ 
						senderKeyJids,
						senderKeyCount: senderKeyJids.length,
						groupAddressingMode,
						totalDevices: devices.length
					}, '🔑 Sending sender keys to group participants')

					const senderKeyMsg: proto.IMessage = {
						senderKeyDistributionMessage: {
							axolotlSenderKeyDistributionMessage: senderKeyDistributionMessage,
							groupId: destinationJid
						}
					}

					// CRITICAL: assertSessions will handle bulk LID migration for sender key recipients
					await assertSessions(senderKeyJids, false)

					const result = await createParticipantNodes(senderKeyJids, senderKeyMsg, extraAttrs)
					shouldIncludeDeviceIdentity = shouldIncludeDeviceIdentity || result.shouldIncludeDeviceIdentity

					participants.push(...result.nodes)
					
					logger.debug({ 
						senderKeyNodes: result.nodes.length,
						participantsCount: participants.length 
					}, '✅ Sender key distribution complete')
				}

				binaryNodeContent.push({
					tag: 'enc',
					attrs: { v: '2', type: 'skmsg' },
					content: ciphertext
				})

				await authState.keys.set({ 'sender-key-memory': { [jid]: senderKeyMap } })
			} else {
				// WHATSMEOW PATTERN: Extract user from ownId (which might be LID)
				const { user: ownUser } = jidDecode(ownId)!

				if (!participant) {
					// If targetDevices is specified (for receipt timeout resends), use only those
					if (targetDevices && targetDevices.length > 0) {
						for (const deviceJid of targetDevices) {
							const decoded = jidDecode(deviceJid)
							if (decoded) {
								devices.push({ 
									user: decoded.user, 
									device: decoded.device,
									wireJid: deviceJid // Use the target device JID as wire JID
								})
							}
						}
						logger.info({
							msgId,
							targetDevices,
							reason: 'receipt_timeout_resend'
						}, 'Sending to specific devices due to missing receipts')
					} else {
						// Normal device resolution with proper addressing consistency
						// Device enumeration with conversation-consistent addressing
						
						// SIMPLIFIED ADDRESSING: Use conversation context to determine addressing mode
						// Target user gets same server type as conversation
						const targetUserServer = isLid ? 'lid' : 's.whatsapp.net'
						devices.push({ 
							user, 
							device: 0,
							wireJid: jidEncode(user, targetUserServer, 0)
						})
						
						// Own user matches conversation addressing mode  
						if (user !== ownUser) {
							const ownUserServer = isLid ? 'lid' : 's.whatsapp.net'
							const ownUserForAddressing = isLid ? jidDecode(meLid!)!.user : jidDecode(meId)!.user
							
							devices.push({ 
								user: ownUserForAddressing, 
								device: 0,
								wireJid: jidEncode(ownUserForAddressing, ownUserServer, 0)
							})
						}

						if (additionalAttributes?.['category'] !== 'peer') {
							// Clear placeholders and enumerate actual devices
							devices.length = 0
							
							// Use conversation-appropriate sender identity
							const senderIdentity = isLid && meLid ? 
								jidEncode(jidDecode(meLid)!.user, 'lid', undefined) : 
								jidEncode(jidDecode(meId)!.user, 's.whatsapp.net', undefined)
							
							logger.debug({ 
								target: jid,
								senderIdentity,
								conversationType: isLid ? 'lid' : 'pn'
							}, 'Enumerating devices with consistent addressing')
							
							// Enumerate devices for sender and target with consistent addressing
							const sessionDevices = await getUSyncDevices([senderIdentity, jid], false, false, isLid ? 'lid' : 'pn')
							devices.push(...sessionDevices)
							
							logger.debug({ 
								deviceCount: devices.length,
								devices: devices.map(d => `${d.user}:${d.device}@${jidDecode(d.wireJid)?.server}`)
							}, 'Device enumeration complete with unified addressing')
						}
					}
				}

				const allJids: string[] = []
				const meJids: string[] = []
				const otherJids: string[] = []
				// WHATSMEOW PATTERN: Also need to check against both PN and LID users
				const { user: mePnUser } = jidDecode(meId)!
				const { user: meLidUser } = meLid ? jidDecode(meLid)! : { user: null }
				
				for (const { user, wireJid } of devices) {
					// WHATSMEOW LOGIC: Skip exact sender device to prevent loops
					const isExactSenderDevice = wireJid === meId || (meLid && wireJid === meLid)
					if (isExactSenderDevice) {
						logger.debug({ wireJid, meId, meLid }, '⏭️ Skipping exact sender device (whatsmeow pattern)')
						continue
					}
					
					// Check if this is our device (could match either PN or LID user)
					const isMe = user === mePnUser || (meLidUser && user === meLidUser)
					
					// DEBUG: Log device classification
					logger.debug({ 
						deviceUser: user, 
						wireJid, 
						mePnUser, 
						meLidUser, 
						isMe,
						classification: isMe ? 'OWN_DEVICE' : 'OTHER_DEVICE'
					}, '🔍 Device classification for DSM logic')
					
					// WHATSMEOW EXACT: Use the wire JID exactly as returned from device enumeration
					// This preserves the correct server format based on what was originally queried
					const jid = wireJid
					
					if (isMe) {
						meJids.push(jid)
					} else {
						otherJids.push(jid)
					}

					allJids.push(jid)
				}

				// SIMPLIFIED DSM: Keep DSM for multi-device sync but remove complex session management
				// Just deliver to all devices - let assertSessions handle session management

				await assertSessions([...otherJids, ...meJids], false)

				logger.debug({ 
					ownDevices: meJids,
					otherDevices: otherJids,
					totalDevices: [...otherJids, ...meJids].length,
					ownDeviceCount: meJids.length,
					otherDeviceCount: otherJids.length
				}, '📤 DSM device allocation for message sending (simplified)')

				const [
					{ nodes: meNodes, shouldIncludeDeviceIdentity: s1 },
					{ nodes: otherNodes, shouldIncludeDeviceIdentity: s2 }
				] = await Promise.all([
					// For own devices: use DSM if available (1:1 chats only)
					createParticipantNodes(meJids, meMsg || message, extraAttrs),
					// For other devices: pass DSM so own devices of recipients get DSM
					createParticipantNodes(otherJids, message, extraAttrs, meMsg)
				])
				participants.push(...meNodes)
				participants.push(...otherNodes)

				shouldIncludeDeviceIdentity = shouldIncludeDeviceIdentity || s1 || s2
			}

			if (participants.length) {
				if (additionalAttributes?.['category'] === 'peer') {
					const peerNode = participants[0]?.content?.[0] as BinaryNode
					if (peerNode) {
						binaryNodeContent.push(peerNode) // push only enc
					}
				} else {
					binaryNodeContent.push({
						tag: 'participants',
						attrs: {},
						content: participants
					})
				}
			}

			// Note: addressing_mode is only used for groups in whatsmeow, not individual chats
			const addressingModeAttrs: Record<string, string> = {}

			const stanza: BinaryNode = {
				tag: 'message',
				attrs: {
					id: msgId,
					to: destinationJid,
					type: getMessageType(message),
					...addressingModeAttrs,
					...(additionalAttributes || {})
				},
				content: binaryNodeContent
			}
			// if the participant to send to is explicitly specified (generally retry recp)
			// ensure the message is only sent to that person
			// if a retry receipt is sent to everyone -- it'll fail decryption for everyone else who received the msg
			if (participant) {
				if (isJidGroup(destinationJid)) {
					stanza.attrs.to = destinationJid
					stanza.attrs.participant = participant.jid
				} else if (areJidsSameUser(participant.jid, meId)) {
					stanza.attrs.to = participant.jid
					stanza.attrs.recipient = destinationJid
				} else {
					stanza.attrs.to = participant.jid
				}
			} else {
				stanza.attrs.to = destinationJid
			}

			if (shouldIncludeDeviceIdentity) {
				;(stanza.content as BinaryNode[]).push({
					tag: 'device-identity',
					attrs: {},
					content: encodeSignedDeviceIdentity(authState.creds.account!, true)
				})

				logger.debug({ jid }, 'adding device identity')
			}

			if (!isNewsletter && buttonType && messages) {
				const buttonsNode = getButtonArgs(messages)
				const filteredButtons = getBinaryFilteredButtons(additionalNodes ? additionalNodes : [])

				if (filteredButtons) {
					;(stanza.content as BinaryNode[]).push(...(additionalNodes || []))
					didPushAdditional = true
				} else {
					;(stanza.content as BinaryNode[]).push(buttonsNode)
				}
			}

			if (isJidUser(destinationJid)) {
				const botNode: BinaryNode = {
					tag: 'bot',
					attrs: {
						biz_bot: '1'
					}
				}

				const filteredBizBot = getBinaryFilteredBizBot(additionalNodes ? additionalNodes : [])

				if (filteredBizBot) {
					;(stanza.content as BinaryNode[]).push(...(additionalNodes || []))
					didPushAdditional = true
				} else {
					;(stanza.content as BinaryNode[]).push(botNode)
				}
			}

			if (!didPushAdditional && additionalNodes && additionalNodes.length > 0) {
				;(stanza.content as BinaryNode[]).push(...additionalNodes)
			}

			logger.debug({ msgId }, `sending message to ${participants.length} devices`)

			await sendNode(stanza)

		})

		return msgId
	}

	const getMessageType = (message: proto.IMessage) => {
		if (message.pollCreationMessage || message.pollCreationMessageV2 || message.pollCreationMessageV3) {
			return 'poll'
		}

		return 'text'
	}

	const getMediaType = (message: proto.IMessage) => {
		if (message.imageMessage) {
			return 'image'
		} else if (message.stickerMessage) {
			return message.stickerMessage.isLottie
				? '1p_sticker'
				: message.stickerMessage.isAvatar
					? 'avatar_sticker'
					: 'sticker'
		} else if (message.videoMessage) {
			return message.videoMessage.gifPlayback ? 'gif' : 'video'
		} else if (message.audioMessage) {
			return message.audioMessage.ptt ? 'ptt' : 'audio'
		} else if (message.ptvMessage) {
			return 'ptv'
		} else if (message.contactMessage) {
			return 'vcard'
		} else if (message.documentMessage) {
			return 'document'
		} else if (message.stickerPackMessage) {
			return 'sticker_pack'
		} else if (message.contactsArrayMessage) {
			return 'contact_array'
		} else if (message.locationMessage) {
			return 'location'
		} else if (message.liveLocationMessage) {
			return 'livelocation'
		} else if (message.listMessage) {
			return 'list'
		} else if (message.listResponseMessage) {
			return 'list_response'
		} else if (message.buttonsResponseMessage) {
			return 'buttons_response'
		} else if (message.orderMessage) {
			return 'order'
		} else if (message.productMessage) {
			return 'product'
		} else if (message.interactiveMessage) {
			return 'interactive'
		} else if (message.interactiveResponseMessage) {
			return 'native_flow_response'
		} else if (/https:\/\/wa\.me\/c\/\d+/.test(message.extendedTextMessage?.text || '')) {
			return 'cataloglink'
		} else if (/https:\/\/wa\.me\/p\/\d+\/\d+/.test(message.extendedTextMessage?.text || '')) {
			return 'productlink'
		} else if (message.extendedTextMessage?.matchedText || message.groupInviteMessage) {
			return 'url'
		}
	}

	const getButtonType = (message: proto.IMessage) => {
		if (message.listMessage) {
			return 'list'
		} else if (message.buttonsMessage) {
			return 'buttons'
		} else if (message.interactiveMessage?.nativeFlowMessage) {
			return 'native_flow'
		}
	}

	const getButtonArgs = (message: proto.IMessage): BinaryNode => {
		const nativeFlow = message.interactiveMessage?.nativeFlowMessage
		const firstButtonName = nativeFlow?.buttons?.[0]?.name
		const nativeFlowSpecials = [
			'mpm',
			'cta_catalog',
			'send_location',
			'call_permission_request',
			'wa_payment_transaction_details',
			'automated_greeting_message_view_catalog'
		]

		if (nativeFlow && (firstButtonName === 'review_and_pay' || firstButtonName === 'payment_info')) {
			// Use simplified structure that Android devices prefer
			return {
				tag: 'biz',
				attrs: {
					native_flow_name: firstButtonName === 'review_and_pay' ? 'order_details' : firstButtonName
				}
			}
		} else if (nativeFlow && firstButtonName && nativeFlowSpecials.includes(firstButtonName)) {
			// Only works for WhatsApp Original, not WhatsApp Business
			return {
				tag: 'biz',
				attrs: {},
				content: [
					{
						tag: 'interactive',
						attrs: {
							type: 'native_flow',
							v: '1'
						},
						content: [
							{
								tag: 'native_flow',
								attrs: {
									v: '2',
									name: firstButtonName
								}
							}
						]
					}
				]
			}
		} else if (nativeFlow || message.buttonsMessage) {
			// It works for whatsapp original and whatsapp business
			return {
				tag: 'biz',
				attrs: {},
				content: [
					{
						tag: 'interactive',
						attrs: {
							type: 'native_flow',
							v: '1'
						},
						content: [
							{
								tag: 'native_flow',
								attrs: {
									v: '9',
									name: 'mixed'
								}
							}
						]
					}
				]
			}
		} else if (message.listMessage) {
			return {
				tag: 'biz',
				attrs: {},
				content: [
					{
						tag: 'list',
						attrs: {
							v: '2',
							type: 'product_list'
						}
					}
				]
			}
		} else {
			return {
				tag: 'biz',
				attrs: {}
			}
		}
	}

	const getPrivacyTokens = async (jids: string[]) => {
		const t = unixTimestampSeconds().toString()
		const result = await query({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'set',
				xmlns: 'privacy'
			},
			content: [
				{
					tag: 'tokens',
					attrs: {},
					content: jids.map(jid => ({
						tag: 'token',
						attrs: {
							jid: jidNormalizedUser(jid),
							t,
							type: 'trusted_contact'
						}
					}))
				}
			]
		})

		return result
	}

	const waUploadToServer = getWAUploadToServer(config, refreshMediaConn)

	const waitForMsgMediaUpdate = bindWaitForEvent(ev, 'messages.media-update')

	const sendStatusMentions = async (content: AnyMessageContent, jids: string[] = []) => {
		const userJid = jidNormalizedUser(authState.creds.me!.id)
		const allUsers = new Set<string>()
		allUsers.add(userJid)

		for (const id of jids) {
			const isGroup = isJidGroup(id)
			const isPrivate = isJidUser(id)

			if (isGroup) {
				try {
					const metadata = (cachedGroupMetadata && (await cachedGroupMetadata(id))) || (await groupMetadata(id))
					const participants = metadata.participants.map(p => jidNormalizedUser(p.id))
					participants.forEach(jid => allUsers.add(jid))
				} catch (error) {
					logger.error(`Error getting metadata for group ${id}: ${error}`)
				}
			} else if (isPrivate) {
				allUsers.add(jidNormalizedUser(id))
			}
		}

		const uniqueUsers = Array.from(allUsers)
		const getRandomHexColor = () =>
			'#' +
			Math.floor(Math.random() * 16777215)
				.toString(16)
				.padStart(6, '0')

		const isMedia = 'image' in content || 'video' in content || 'audio' in content
		const isAudio = !!(content as any).audio

		const messageContent = { ...content }

		if (isMedia && !isAudio) {
			if ((messageContent as any).text) {
				;(messageContent as any).caption = (messageContent as any).text
				delete (messageContent as any).text
			}

			delete (messageContent as any).ptt
			delete (messageContent as any).font
			delete (messageContent as any).backgroundColor
			delete (messageContent as any).textColor
		}

		if (isAudio) {
			delete (messageContent as any).text
			delete (messageContent as any).caption
			delete (messageContent as any).font
			delete (messageContent as any).textColor
		}

		const font = !isMedia ? (content as any).font || Math.floor(Math.random() * 9) : undefined
		const textColor = !isMedia ? (content as any).textColor || getRandomHexColor() : undefined
		const backgroundColor = !isMedia || isAudio ? (content as any).backgroundColor || getRandomHexColor() : undefined
		const ptt = isAudio ? (typeof (content as any).ptt === 'boolean' ? (content as any).ptt : true) : undefined

		let msg: any
		let mediaHandle: string | undefined
		try {
			msg = await generateWAMessage(STORIES_JID, messageContent, {
				logger,
				userJid,
				getUrlInfo: (text: string) =>
					getUrlInfo(text, {
						thumbnailWidth: linkPreviewImageThumbnailWidth,
						fetchOpts: { timeout: 3000, ...(axiosOptions || {}) },
						logger,
						uploadImage: generateHighQualityLinkPreview ? waUploadToServer : undefined
					}),
				upload: async (encFilePath: string, opts: any) => {
					const up = await waUploadToServer(encFilePath, { ...opts })
					mediaHandle = up.mediaUrl
					return up
				},
				mediaCache: config.mediaCache,
				options: config.options,
				font,
				textColor,
				backgroundColor,
				ptt
			} as any)
		} catch (error) {
			logger.error(`Error generating message: ${error}`)
			throw error
		}

		await relayMessage(STORIES_JID, msg.message, {
			messageId: msg.key.id!,
			statusJidList: uniqueUsers,
			additionalNodes: [
				{
					tag: 'meta',
					attrs: {},
					content: [
						{
							tag: 'mentioned_users',
							attrs: {},
							content: jids.map(jid => ({
								tag: 'to',
								attrs: { jid: jidNormalizedUser(jid) }
							}))
						}
					]
				}
			]
		})

		for (const id of jids) {
			try {
				const normalizedId = jidNormalizedUser(id)
				const isPrivate = isJidUser(normalizedId)
				const type = isPrivate ? 'statusMentionMessage' : 'groupStatusMentionMessage'

				const protocolMessage = {
					[type]: {
						message: {
							protocolMessage: {
								key: msg.key,
								type: 25
							}
						}
					},
					messageContextInfo: {
						messageSecret: randomBytes(32)
					}
				}

				const statusMsg = await generateWAMessageFromContent(normalizedId, protocolMessage, { userJid })

				await relayMessage(normalizedId, statusMsg.message!, {
					additionalNodes: [
						{
							tag: 'meta',
							attrs: isPrivate ? { is_status_mention: 'true' } : { is_group_status_mention: 'true' }
						}
					]
				})

				await delay(2000)
			} catch (error) {
				logger.error(`Error sending to ${id}: ${error}`)
			}
		}

		return msg
	}

	const sendAlbumMessage = async (
		jid: string,
		medias: AnyMessageContent[],
		options: MiscMessageGenerationOptions = {}
	) => {
		const userJid = authState.creds.me!.id

		for (const media of medias) {
			if (!('image' in media) && !('video' in media)) throw new TypeError(`medias[i] must have image or video property`)
		}

		const time = (options as any).delay || 500
		delete (options as any).delay

		const album = await generateWAMessageFromContent(
			jid,
			{
				albumMessage: {
					expectedImageCount: medias.filter(media => 'image' in media).length,
					expectedVideoCount: medias.filter(media => 'video' in media).length,
					...options
				}
			} as any,
			{ userJid, ...options }
		)

		await relayMessage(jid, album.message!, { messageId: album.key.id! })

		let mediaHandle: string | undefined
		let msg: any

		for (const i in medias) {
			const media = medias[i]
			if (!media) continue

			if ('image' in media) {
				msg = await generateWAMessage(
					jid,
					{
						...media,
						...options
					},
					{
						userJid,
						upload: async (encFilePath: string, opts: any) => {
							const up = await waUploadToServer(encFilePath, { ...opts, newsletter: isJidNewsletter(jid) })
							mediaHandle = up.mediaUrl // Fixed: use mediaUrl instead of handle
							return up
						},
						...options
					}
				)
			} else if ('video' in media) {
				msg = await generateWAMessage(
					jid,
					{
						...media,
						...options
					},
					{
						userJid,
						upload: async (encFilePath: string, opts: any) => {
							const up = await waUploadToServer(encFilePath, { ...opts, newsletter: isJidNewsletter(jid) })
							mediaHandle = up.mediaUrl // Fixed: use mediaUrl instead of handle
							return up
						},
						...options
					}
				)
			}

			if (msg) {
				msg.message!.messageContextInfo = {
					messageSecret: randomBytes(32),
					messageAssociation: {
						associationType: 1,
						parentMessageKey: album.key
					}
				}
			}

			await relayMessage(jid, msg!.message, { messageId: msg!.key.id! })
			await delay(time)
		}

		return album
	}

	return {
		...sock,
		getPrivacyTokens,
		assertSessions,
		relayMessage,
		sendReceipt,
		sendReceipts,
		readMessages,
		refreshMediaConn,
		waUploadToServer,
		fetchPrivacySettings,
		sendPeerDataOperationMessage,
		createParticipantNodes,
		getUSyncDevices,
		sendStatusMentions,
		sendAlbumMessage,
		// Built-in getMessage implementation (replaces external getMessage)
		getMessage: messageCache.getMessage.bind(messageCache),
		// Message cache for monitoring and stats
		messageCache,
		updateMediaMessage: async (message: proto.IWebMessageInfo) => {
			const content = assertMediaContent(message.message)
			const mediaKey = content.mediaKey!
			const meId = authState.creds.me!.id
			const node = await encryptMediaRetryRequest(message.key, mediaKey, meId)

			let error: Error | undefined = undefined
			await Promise.all([
				sendNode(node),
				waitForMsgMediaUpdate(async update => {
					const result = update.find(c => c.key.id === message.key.id)
					if (result) {
						if (result.error) {
							error = result.error
						} else {
							try {
								const media = await decryptMediaRetryData(result.media!, mediaKey, result.key.id!)
								if (media.result !== proto.MediaRetryNotification.ResultType.SUCCESS) {
									const resultStr = proto.MediaRetryNotification.ResultType[media.result!]
									throw new Boom(`Media re-upload failed by device (${resultStr})`, {
										data: media,
										statusCode: getStatusCodeForMediaRetry(media.result!) || 404
									})
								}

								content.directPath = media.directPath
								content.url = getUrlFromDirectPath(content.directPath!)

								logger.debug({ directPath: media.directPath, key: result.key }, 'media update successful')
							} catch (err: any) {
								error = err
							}
						}

						return true
					}
				})
			])

			if (error) {
				throw error
			}

			ev.emit('messages.update', [{ key: message.key, update: { message: message.message } }])

			return message
		},
		sendMessage: async (jid: string, content: AnyMessageContent, options: MiscMessageGenerationOptions = {}) => {
			const userJid = authState.creds.me!.id
			if (
				typeof content === 'object' &&
				'disappearingMessagesInChat' in content &&
				typeof content['disappearingMessagesInChat'] !== 'undefined' &&
				isJidGroup(jid)
			) {
				const { disappearingMessagesInChat } = content
				const value =
					typeof disappearingMessagesInChat === 'boolean'
						? disappearingMessagesInChat
							? WA_DEFAULT_EPHEMERAL
							: 0
						: disappearingMessagesInChat
				await groupToggleEphemeral(jid, value)
			} else {
				// Generate message with the original JID to preserve user intent
				const fullMsg = await generateWAMessage(jid, content, {
					logger,
					userJid,
					getUrlInfo: text =>
						getUrlInfo(text, {
							thumbnailWidth: linkPreviewImageThumbnailWidth,
							fetchOpts: {
								timeout: 3_000,
								...(axiosOptions || {})
							},
							logger,
							uploadImage: generateHighQualityLinkPreview ? waUploadToServer : undefined
						}),
					//TODO: CACHE
					getProfilePicUrl: sock.profilePictureUrl,
					upload: waUploadToServer,
					mediaCache: config.mediaCache,
					options: config.options,
					messageId: generateMessageIDV2(sock.user?.id),
					...options
				})
				const isDeleteMsg = 'delete' in content && !!content.delete
				const isEditMsg = 'edit' in content && !!content.edit
				const isPinMsg = 'pin' in content && !!content.pin
				const isPollMessage = 'poll' in content && !!content.poll
				const additionalAttributes: BinaryNodeAttributes = {}
				const additionalNodes: BinaryNode[] = []
				// required for delete
				if (isDeleteMsg) {
					// if the chat is a group, and I am not the author, then delete the message as an admin
					if (isJidGroup(content.delete?.remoteJid as string) && !content.delete?.fromMe) {
						additionalAttributes.edit = '8'
					} else {
						additionalAttributes.edit = '7'
					}
				} else if (isEditMsg) {
					additionalAttributes.edit = '1'
				} else if (isPinMsg) {
					additionalAttributes.edit = '2'
				} else if (isPollMessage) {
					additionalNodes.push({
						tag: 'meta',
						attrs: {
							polltype: 'creation'
						}
					} as BinaryNode)
				}

				if ('cachedGroupMetadata' in options) {
					console.warn(
						'cachedGroupMetadata in sendMessage are deprecated, now cachedGroupMetadata is part of the socket config.'
					)
				}

				await relayMessage(jid, fullMsg.message!, {
					messageId: fullMsg.key.id!,
					useCachedGroupMetadata: options.useCachedGroupMetadata,
					additionalAttributes,
					statusJidList: options.statusJidList,
					additionalNodes
				})
				
				// DUAL-IDENTITY CACHING: Cache with both wire JID and encryption identity
				// This ensures retry receipts work regardless of which identity WhatsApp uses
				const wireJid = jid  // Original JID passed by user (wire identity)
				const msgId = fullMsg.key.id!
				const message = fullMsg.message!
				
				// Primary cache: Always cache with wire JID (what's in message.key.remoteJid)
				messageCache.addRecentMessage(wireJid, msgId, message)
				logger.trace({ wireJid, msgId }, 'Message cached with wire JID (primary)')
				
				// Secondary cache: Also cache with LID if different from wire JID (for retry compatibility)
				if (wireJid.includes('@s.whatsapp.net') && !wireJid.includes('bot')) {
					try {
						const lidStore = signalRepository.getLIDMappingStore()
						const lidForPN = await lidStore.getLIDForPN(wireJid)
						
						if (lidForPN && lidForPN.includes('@lid') && lidForPN !== wireJid) {
							// Cache the same message with LID identity for retry receipt compatibility
							messageCache.addRecentMessage(lidForPN, msgId, message)
							logger.trace({ wireJid, lidJid: lidForPN, msgId }, 'Message also cached with LID identity for retry compatibility')
						}
					} catch (error) {
						logger.debug({ wireJid, error }, 'Failed to cache with LID identity')
					}
				}

				if (config.emitOwnEvents) {
					process.nextTick(() => {
						processingMutex.mutex(() => upsertMessage(fullMsg, 'append'))
					})
				}

				return fullMsg
			}
		}
	}
}