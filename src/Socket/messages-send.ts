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
import { PrivacyTokenUtils } from '../Signal/privacy-tokens'
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
	

	// Helper function to get privacy token with LID-PN cross-referencing (enhanced from whatsmeow)
	const getPrivacyToken = async (jid: string): Promise<Buffer | null> => {
		try {
			// Use the privacy token manager for proper LID-PN cross-referencing
			const privacyTokenManager = signalRepository.getPrivacyTokenManager()
			const tokenData = await privacyTokenManager.getPrivacyToken(jid)
			
			if (tokenData?.token && Buffer.isBuffer(tokenData.token)) {
				logger.trace({ jid }, 'privacy token found for message sending with LID cross-referencing')
				return tokenData.token
			}
			
			return null
		} catch (error) {
			logger.debug({ jid, error }, 'failed to get privacy token')
			return null
		}
	}

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

	/** Enhanced device info that preserves wire JID format and session context */
	type DeviceWithWireJid = JidWithDevice & {
		wireJid: string // The exact JID format that should be used in wire protocol
		sessionContext?: {
			targetSession: string
			senderIdentity: string  
			addressingMode: 'lid' | 'pn'
		}
	}

	/** Fetch all the devices we've to send a message to */
	const getUSyncDevices = async (jids: string[], useCache: boolean, ignoreZeroDevices: boolean, disableAutoMigration = false): Promise<DeviceWithWireJid[]> => {
		const deviceResults: DeviceWithWireJid[] = []

		// DEBUG: Log input JIDs to understand what's being passed
		logger.debug({ jids, useCache, ignoreZeroDevices, disableAutoMigration }, '🔍 getUSyncDevices called with JIDs')

		if (!useCache) {
			logger.debug('not using cache for devices')
		}

		const toFetch: string[] = []
		jids = Array.from(new Set(jids))
		
		// CRITICAL FIX: Remove PN duplicates when LID versions exist (but allow both for own devices)
		// If both "102765716062358@lid" and "102765716062358@s.whatsapp.net" are present, 
		// prefer the LID version for contacts, but keep both for own devices
		if (!disableAutoMigration) {
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
			
			// Second pass: filter out PN versions if LID exists (for contacts only)
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
		} else {
			logger.debug({ disableAutoMigration: true }, '✅ Multi-session delivery: keeping all PN and LID sessions')
		}

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
			
			// CRITICAL FIX: Check if this is our own device FIRST to disable auto-migration
			const currentUserJid = jidNormalizedUser(authState.creds.me!.id)
			const isOwnDevice = jidNormalizedUser(jid) === currentUserJid
			
			// For own devices, disable auto-migration to prevent ratchet corruption
			if (isOwnDevice) {
				disableAutoMigration = true
				logger.info({ jid, currentUser: currentUserJid }, '🔄 Own device detected: disabling auto-migration to preserve ratchet independence')
			}
			
			// Check if this is an explicit PN device JID
			const originalDecoded = jidDecode(jid)
			const originalDevice = originalDecoded?.device
			const isExplicitPNDevice = typeof originalDevice === 'number' && originalDevice >= 0
			
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
			
			// WHATSMEOW EXACT: Automatic PN→LID migration when LID mapping exists
			// Even if user typed a phone number, prefer LID when available
			// BUT: Skip auto-migration if we're doing intentional multi-session delivery OR for own devices
			if (!disableAutoMigration) {
				try {
					const lidMapping = signalRepository.getLIDMappingStore()
					const lidForPN = await lidMapping.getLIDForPN(jid)
					
					if (lidForPN && lidForPN.includes('@lid')) {
					// Found LID mapping - use LID instead of PN (whatsmeow pattern)
					logger.info({ originalPN: jid, lidAddress: lidForPN }, '✅ Auto-migrating PN to LID (whatsmeow LID priority)')
					
					// Process as LID address (same logic as LID processing above)
					const lidSignalId = signalRepository.jidToSignalProtocolAddress(lidForPN)
					const lidSessions = await authState.keys.get('session', [lidSignalId])
					const hasLIDSession = !!lidSessions[lidSignalId]
					
					// CRITICAL: When auto-migrating PN→LID, the wire JID should be LID format
					// This matches whatsmeow's behavior where migrated JIDs use LID in the envelope
					const lidDecoded = jidDecode(lidForPN)
					const lidUser = lidDecoded?.user
					
					if (hasLIDSession) {
						// CRITICAL FIX: Use the actual device ID from the original JID, not hardcoded 0
						const originalDecoded = jidDecode(jid)
						const actualDeviceId = originalDecoded?.device || 0
						logger.info({ lidForPN, actualDeviceId }, '✅ Found existing LID session for migrated address')
						deviceResults.push({ 
							user: lidUser!, // Use LID user for internal tracking
							device: actualDeviceId, // Use actual device ID from original JID
							wireJid: jidEncode(lidUser!, 'lid', actualDeviceId) // Wire JID uses LID format with correct device ID
						})
						// Skip normal PN processing since we're using LID
						continue
					} else {
						// CRITICAL FIX: Check if this is our own device vs contact device
						const currentUserJid = jidNormalizedUser(authState.creds.me!.id)
						const isOwnDevice = jidNormalizedUser(jid) === currentUserJid
						
						if (isOwnDevice) {
							// CRITICAL FIX: For own devices, DON'T auto-migrate to prevent ratchet corruption
							// Apply the same approach as contacts - let both PN and LID sessions coexist
							logger.info({ lidForPN, currentUser: currentUserJid, originalJid: jid }, '🔄 Own device: skipping auto-migration to preserve ratchet independence')
							// DON'T create LID device here, DON'T skip PN processing
							// Fall through to normal PN processing to maintain dual sessions like contacts
						} else {
							// For contact devices, fall back to PN when LID session missing
							logger.warn({ lidForPN, contact: jid }, '❌ Contact has LID mapping but no LID session - falling back to PN session creation')
							logger.info({ originalPN: jid }, '🔄 Falling back to PN session creation for contact without LID session')
							// Don't continue here - fall through to normal PN processing
						}
					}
				}
				} catch (error) {
					logger.debug({ jid, error }, 'Failed to check LID mapping during PN processing')
				}
			} else {
				logger.debug({ jid }, '⏭️ Skipping auto-migration for multi-session delivery')
			}
			
			// Continue with normal PN processing if no LID mapping found
			logger.debug({ jid, user }, '📞 Processing PN address without LID mapping')
			
			if (useCache) {
				const devices = userDevicesCache.get(user!) as JidWithDevice[]
				if (devices) {
					// Convert cached devices to wire format
					const devicesWithWire = devices.map(d => ({
						...d,
						wireJid: jidEncode(d.user, 's.whatsapp.net', d.device)
					}))
					deviceResults.push(...devicesWithWire)

					logger.debug({ user, deviceCount: devices.length }, '✅ Found cached PN devices')
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

			for (const item of extracted) {
				deviceMap[item.user] = deviceMap[item.user] || []
				deviceMap[item.user]?.push(item)

				// Convert to DeviceWithWireJid - devices from PN enumeration use PN wire format
				const deviceWithWire: DeviceWithWireJid = {
					...item,
					wireJid: jidEncode(item.user, 's.whatsapp.net', item.device)
				}
				deviceResults.push(deviceWithWire)
				logger.debug({ user: item.user, device: item.device, wireJid: deviceWithWire.wireJid }, '✅ Added PN device to results')
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

	// Session recreation cache for whatsmeow pattern (separate from retry cache)
	const sessionRecreateCache = new NodeCache({ stdTTL: 60 * 60 }) // 1 hour TTL
	
	// Helper function for whatsmeow session recreation logic
	const shouldRecreateSessionForRetry = async (retryCount: number, participant: string): Promise<{ recreate: boolean, reason: string }> => {
		// Check if we have a session for this participant
		const sessionKey = signalRepository.jidToSignalProtocolAddress(participant)
		const participantSessions = await authState.keys.get('session', [sessionKey])
		const hasSession = Object.keys(participantSessions).length > 0 && participantSessions[sessionKey]
		
		if (!hasSession) {
			return { recreate: true, reason: "no session exists with participant" }
		}
		
		// Only recreate after 2+ failed attempts (whatsmeow pattern)
		if (retryCount < 2) {
			return { recreate: false, reason: "retry count too low" }
		}
		
		// Rate limiting: only recreate once per hour per participant (whatsmeow pattern)  
		const sessionRecreateKey = `session-recreate:${participant}`
		const lastRecreation = sessionRecreateCache.get(sessionRecreateKey) as number
		const oneHourAgo = Date.now() - (60 * 60 * 1000)
		
		if (!lastRecreation || lastRecreation < oneHourAgo) {
			sessionRecreateCache.set(sessionRecreateKey, Date.now())
			return { recreate: true, reason: "retry count >= 2 and over an hour since last recreation" }
		}
		
		return { recreate: false, reason: "session recreated recently" }
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
			// CRITICAL FIX: Check for migrated LID sessions before fetching new PN sessions
			const lidMapping = signalRepository.getLIDMappingStore()
			const addrs = jids.map(jid => signalRepository.jidToSignalProtocolAddress(jid))
			const sessions = await authState.keys.get('session', addrs)
			
			for (const jid of jids) {
				const signalId = signalRepository.jidToSignalProtocolAddress(jid)
				let hasSession = !!sessions[signalId]
				
				// If no PN session found, check if there's a migrated LID session
				let jidToFetch = jid // Default to original JID
				if (!hasSession && jid.includes('@s.whatsapp.net')) {
					try {
						// CRITICAL: Normalize JID to user level for LID mapping lookup
						const normalizedJid = jidNormalizedUser(jid)
						logger.debug({ originalJid: jid, normalizedJid }, 'Checking for LID mapping before creating PN session')
						const lidForPN = await lidMapping.getLIDForPN(normalizedJid)
						logger.debug({ jid, normalizedJid, lidForPN }, 'LID mapping lookup result')
						
						if (lidForPN && lidForPN.includes('@lid')) {
							// CRITICAL: Preserve device ID from original JID
							const originalDecoded = jidDecode(jid)
							const actualDeviceId = originalDecoded?.device || 0
							const lidDecoded = jidDecode(lidForPN)
							const lidWithDevice = jidEncode(lidDecoded?.user!, 'lid', actualDeviceId)
							
							// Check if LID session exists (with correct device ID)
							const lidSignalId = signalRepository.jidToSignalProtocolAddress(lidWithDevice)
							const lidSessions = await authState.keys.get('session', [lidSignalId])
							hasSession = !!lidSessions[lidSignalId]
							
							if (hasSession) {
								logger.info({ jid, lidForPN: lidWithDevice, actualDeviceId }, '✅ Found migrated LID session, skipping PN fetch')
							} else {
								// CRITICAL FIX: Check if this is our own device vs contact device
								const currentUserJid = jidNormalizedUser(authState.creds.me!.id)
								const isOwnDevice = jidNormalizedUser(normalizedJid) === currentUserJid
								
								if (isOwnDevice) {
									// CRITICAL FIX: For own devices, create BOTH PN and LID sessions
									// This maintains dual session availability like contacts
									logger.info({ jid, lidForPN: lidWithDevice, currentUser: currentUserJid, actualDeviceId }, '🔄 Own device: creating BOTH PN and LID sessions')
									
									// Add both PN and LID to fetch list (only if not already added)
									if (!jidsRequiringFetch.includes(jid)) {
										jidsRequiringFetch.push(jid) // Original PN address
										logger.debug({ originalJid: jid }, 'Adding PN address to fetch list for own device')
									}
									if (!jidsRequiringFetch.includes(lidWithDevice)) {
										jidsRequiringFetch.push(lidWithDevice) // LID address with correct device ID
										logger.debug({ lidJid: lidWithDevice }, 'Adding LID address to fetch list for own device')
									}
									
									// Skip setting jidToFetch since we already added both to the fetch list
									continue
								} else {
									// For contact devices, prefer LID session creation when mapping exists
									logger.info({ jid, lidForPN: lidWithDevice, contact: normalizedJid }, '🔄 Contact has LID mapping - preferring LID session creation')
									jidToFetch = lidWithDevice // Use LID address with correct device ID
									hasSession = false // Ensure session creation continues
								}
							}
						} else {
							logger.debug({ jid }, 'No LID mapping found, will create PN session')
						}
					} catch (error) {
						logger.error({ jid, error }, 'Failed to check LID mapping')
					}
				}
				
				// CRITICAL FIX: Use the determined JID (could be LID or PN) for session creation
				if (!hasSession) {
					if (jidToFetch.includes('@lid')) {
						logger.debug({ originalJid: jid, lidJid: jidToFetch }, 'Adding LID address to fetch list (from mapping)')
						jidsRequiringFetch.push(jidToFetch)
					} else if (jidToFetch.includes('@s.whatsapp.net')) {
						logger.debug({ jid: jidToFetch }, 'Adding PN address to fetch list for new PN session creation')
						jidsRequiringFetch.push(jidToFetch)
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
		const meLidUser = authState.creds.me?.lid ? jidDecode(authState.creds.me.lid)?.user : null

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
					
					// WIRE JID: Determine encryption identity (following whatsmeow's approach)
					let encryptionJid = wireJid
					
					// SEQUENTIAL ENCRYPTION: Encrypt with the determined identity
					const { type, ciphertext } = await signalRepository.encryptMessage({ 
						jid: encryptionJid,  // Use LID if available, PN otherwise
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

		let shouldIncludeDeviceIdentity = false

		let { user, server } = jidDecode(jid)!
		const statusJid = 'status@broadcast'
		const isGroup = server === 'g.us'
		const isStatus = jid === statusJid
		let isLid = server === 'lid'
		const isNewsletter = server === 'newsletter'
		
		// WHATSMEOW EXACT: LID Priority - Automatic PN→LID migration when LID mapping exists
		// MULTI-SESSION DELIVERY: Collect all available sessions for this contact
		const targetSessions: string[] = [jid] // Always include user's explicit address
		let primarySession = jid // Keep user's original choice as primary
		
		if (!isGroup && !isStatus && !isNewsletter) {
			try {
				const lidMapping = signalRepository.getLIDMappingStore()
				
				if (!isLid && server === 's.whatsapp.net') {
					// User provided PN - check if LID session also exists
					const lidForPN = await lidMapping.getLIDForPN(jid)
					if (lidForPN && lidForPN.includes('@lid') && !targetSessions.includes(lidForPN)) {
						targetSessions.push(lidForPN)
						logger.debug({ originalPN: jid, foundLID: lidForPN }, 'Adding LID session for multi-session delivery')
					}
				} else if (isLid) {
					// User provided LID - check if PN session also exists  
					const pnForLID = await lidMapping.getPNForLID(jid)
					if (pnForLID && pnForLID.includes('@s.whatsapp.net') && !targetSessions.includes(pnForLID)) {
						targetSessions.push(pnForLID)
						logger.debug({ originalLID: jid, foundPN: pnForLID }, 'Adding PN session for multi-session delivery')
					}
				}
			} catch (error) {
				logger.debug({ jid, error }, 'Failed to check additional sessions during message sending')
			}
		}
		
		if (targetSessions.length > 1) {
			logger.info({ 
				userInput: jid, 
				primarySession, 
				allSessions: targetSessions,
				sessionCount: targetSessions.length 
			}, '📡 Multi-session delivery: sending to all available sessions')
		} else {
			logger.debug({ 
				userInput: jid, 
				singleSession: targetSessions[0] 
			}, '📡 Single-session delivery: no additional sessions found')
		}
		
		// Use primary session for addressing mode determination
		let finalJid = primarySession

		// WHATSMEOW PATTERN: Use LID identity when sending to HiddenUserServer (lid)
		let ownId = meId
		if (isLid && meLid) {
			ownId = meLid
			logger.debug({ to: jid, ownId }, 'Using LID identity for HiddenUserServer message')
		}

		msgId = msgId || generateMessageIDV2(sock.user?.id)
		useUserDevicesCache = useUserDevicesCache !== false
		useCachedGroupMetadata = useCachedGroupMetadata !== false && !isStatus

		const participants: BinaryNode[] = []
		const destinationJid = !isStatus ? finalJid : statusJid

		// PRIVACY TOKENS: Get privacy token for recipient (following whatsmeow approach)
		const privacyToken = !isGroup && !isStatus ? await getPrivacyToken(destinationJid) : null
		
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

				// Add privacy token for newsletter if available (following whatsmeow approach)
				if (privacyToken) {
					binaryNodeContent.push(PrivacyTokenUtils.createTokenNode(privacyToken))
					logger.debug({ msgId, to: jid }, 'included privacy token in newsletter message')
				}

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
						additionalAttributes = {
							...additionalAttributes,
							addressing_mode: groupData?.addressingMode || 'pn'
						}
					}

					const additionalDevices = await getUSyncDevices(participantsList, !!useUserDevicesCache, false)
					devices.push(...additionalDevices)
				}

				const patched = await patchMessageBeforeSending(message)

				if (Array.isArray(patched)) {
					throw new Boom('Per-jid patching is not supported in groups')
				}

				const bytes = encodeWAMessage(patched)

				// WHATSMEOW PATTERN: Use LID identity for group sender key when sending to LID groups
				const groupSenderIdentity = isLid && meLid ? meLid : meId
				
				const { ciphertext, senderKeyDistributionMessage } = await signalRepository.encryptGroupMessage({
					group: destinationJid,
					data: bytes,
					meId: groupSenderIdentity
				})

				const senderKeyJids: string[] = []
				// ensure a connection is established with every device
				for (const { user, device } of devices) {
					const jid = jidEncode(user, groupData?.addressingMode === 'lid' ? 'lid' : 's.whatsapp.net', device)
					const hasKey = !!senderKeyMap[jid]
					if (!hasKey || !!participant) {
						senderKeyJids.push(jid)
						// store that this person has had the sender keys sent to them
						senderKeyMap[jid] = true
					}
				}

				// if there are some participants with whom the session has not been established
				// if there are, we re-send the senderkey
				if (senderKeyJids.length) {
					logger.debug({ senderKeyJids }, 'sending new sender key')

					const senderKeyMsg: proto.IMessage = {
						senderKeyDistributionMessage: {
							axolotlSenderKeyDistributionMessage: senderKeyDistributionMessage,
							groupId: destinationJid
						}
					}

					await assertSessions(senderKeyJids, false)

					const result = await createParticipantNodes(senderKeyJids, senderKeyMsg, extraAttrs)
					shouldIncludeDeviceIdentity = shouldIncludeDeviceIdentity || result.shouldIncludeDeviceIdentity

					participants.push(...result.nodes)
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
						// Determine the addressing mode based on target sessions
						const hasLidSession = targetSessions.some(session => session.includes('@lid'))
						const hasPnSession = targetSessions.some(session => session.includes('@s.whatsapp.net'))
						
						// Create placeholder entries for target user
						const targetUserServer = hasLidSession ? 'lid' : 's.whatsapp.net'
						devices.push({ 
							user, 
							device: 0,
							wireJid: jidEncode(user, targetUserServer, 0)
						})
						
						// Create placeholder entries for own user with proper addressing consistency
						if (user !== ownUser) {
							// If target has LID and we have LID capability, use LID for own devices too
							const ownUserServer = (hasLidSession && meLid) ? 'lid' : 's.whatsapp.net'
							const ownUserForAddressing = (hasLidSession && meLid) ? jidDecode(meLid)!.user : ownUser
							
							devices.push({ 
								user: ownUserForAddressing, 
								device: 0,
								wireJid: jidEncode(ownUserForAddressing, ownUserServer, 0)
							})
						}

						if (additionalAttributes?.['category'] !== 'peer') {
							// MULTI-SESSION DELIVERY: Maintain addressing mode consistency per session
							// For each recipient session type, use matching sender identity
							devices.length = 0 // Clear placeholders
							
							for (const targetSession of targetSessions) {
								const targetIsLid = jidDecode(targetSession)?.server === 'lid'
								
								// ADDRESSING CONSISTENCY: Match sender identity to recipient session type
								let senderIdentity: string
								if (targetIsLid && meLid) {
									// LID recipient → use LID sender identity
									senderIdentity = jidEncode(jidDecode(meLid)!.user, 'lid', undefined)
								} else {
									// PN recipient → use PN sender identity  
									senderIdentity = jidEncode(jidDecode(meId)!.user, 's.whatsapp.net', undefined)
								}
								
								logger.debug({ 
									targetSession,
									targetIsLid,
									senderIdentity,
									reason: 'addressing_consistency'
								}, 'Session-specific device enumeration for consistent addressing')
								
								// Enumerate devices for this specific session pair
								// MULTI-SESSION MODE: Enable enumeration for both session types
								const sessionDevices = await getUSyncDevices([senderIdentity, targetSession], false, false, false)
								
								// Add devices with session context - ensure proper wire JID format
								const devicesWithContext = sessionDevices.map(device => {
									// Ensure wireJid matches the session addressing mode
									let correctedWireJid = device.wireJid
									
									// If this is for a LID target session, ensure LID devices use LID wire format
									if (targetIsLid && device.wireJid.includes('@s.whatsapp.net')) {
										correctedWireJid = jidEncode(device.user, 'lid', device.device)
									}
									// If this is for a PN target session, ensure PN devices use PN wire format  
									else if (!targetIsLid && device.wireJid.includes('@lid')) {
										correctedWireJid = jidEncode(device.user, 's.whatsapp.net', device.device)
									}
									
									return {
										...device,
										wireJid: correctedWireJid,
										sessionContext: {
											targetSession,
											senderIdentity,
											addressingMode: targetIsLid ? 'lid' as const : 'pn' as const
										}
									}
								})
								
								devices.push(...devicesWithContext)
							}
							
							// Remove duplicates while preserving session context
							const uniqueDevices = devices.filter((device, index, arr) => 
								arr.findIndex(d => d.wireJid === device.wireJid) === index
							)
							devices.length = 0
							devices.push(...uniqueDevices)
							
							logger.debug({ 
								deviceCount: devices.length,
								devices: devices.map(d => `${d.user}:${d.device}@${jidDecode(d.wireJid)?.server}`),
								sessionsTargeted: targetSessions.length,
								uniqueDevices: uniqueDevices.length
							}, 'Multi-session enumeration complete with addressing consistency')
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

			// Add privacy token to content if available (following whatsmeow approach)
			if (privacyToken) {
				binaryNodeContent.push(PrivacyTokenUtils.createTokenNode(privacyToken))
				logger.debug({ msgId, to: destinationJid }, 'included privacy token in message')
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
				
				// Cache message using simplified whatsmeow approach with wire-encryption separation
				// CRITICAL: Use original JID as wire JID, not the migrated LID
				const wireJid = jid  // Original JID passed by user
				const msgId = fullMsg.key.id!
				const message = fullMsg.message!
				
				// Cache with wire JID (primary)
				messageCache.addRecentMessage(wireJid, msgId, message)
				logger.trace({ remoteJid: wireJid, msgId }, 'Message cached with wire JID')
				
				// WHATSMEOW PATTERN: Also cache with LID address if different from wire address
				if (wireJid.includes('@s.whatsapp.net') && !wireJid.includes('bot')) {
					try {
						const lidStore = signalRepository.getLIDMappingStore()
						const lidForPN = await lidStore.getLIDForPN(wireJid)
						
						if (lidForPN && lidForPN.includes('@lid') && lidForPN !== wireJid) {
							// Cache the same message with LID address for retry receipt compatibility
							messageCache.addRecentMessage(lidForPN, msgId, message)
							logger.trace({ lidJid: lidForPN, msgId }, 'Message also cached with LID address')
						}
					} catch (error) {
						logger.warn({ wireJid, error }, 'Failed to cache with LID address')
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