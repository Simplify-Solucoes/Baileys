import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import type { SignalRepository, WAMessage, WAMessageKey, AddressingMode } from '../Types'
import {
	areJidsSameUser,
	type BinaryNode,
	isJidBroadcast,
	isJidGroup,
	isJidMetaIa,
	isJidNewsletter,
	isJidStatusBroadcast,
	isJidUser,
	isLidUser,
	jidDecode,
	jidEncode,
	jidNormalizedUser
} from '../WABinary'
import { unpadRandomMax16 } from './generics'
import type { ILogger } from './logger'
import { determineLIDEncryptionJid } from './decode-wa-message-lid'

export const NO_MESSAGE_FOUND_ERROR_TEXT = 'Message absent from node'
export const MISSING_KEYS_ERROR_TEXT = 'Key used already or never filled'

/**
 * Extract addressing mode and alternative identities from message stanza
 * Following whatsmeow's approach in message.go:79-92
 */
export const extractAddressingContext = (stanza: BinaryNode, _from: string, _participant?: string) => {
	const addressingMode = (stanza.attrs.addressing_mode as AddressingMode) || 'pn'
	let senderAlt: string | undefined
	let recipientAlt: string | undefined
	
	if (addressingMode === 'lid') {
		// Message is LID-addressed: sender is LID, extract corresponding PN
		senderAlt = stanza.attrs.participant_pn || stanza.attrs.sender_pn
		recipientAlt = stanza.attrs.recipient_pn
	} else {
		// Message is PN-addressed: sender is PN, extract corresponding LID
		senderAlt = stanza.attrs.participant_lid || stanza.attrs.sender_lid
		recipientAlt = stanza.attrs.recipient_lid
	}
	
	return {
		addressingMode,
		senderAlt,
		recipientAlt
	}
}

export const NACK_REASONS = {
	ParsingError: 487,
	UnrecognizedStanza: 488,
	UnrecognizedStanzaClass: 489,
	UnrecognizedStanzaType: 490,
	InvalidProtobuf: 491,
	InvalidHostedCompanionStanza: 493,
	MissingMessageSecret: 495,
	SignalErrorOldCounter: 496,
	MessageDeletedOnPeer: 499,
	UnhandledError: 500,
	UnsupportedAdminRevoke: 550,
	UnsupportedLIDGroup: 551,
	DBOperationFailed: 552
}

type MessageType =
	| 'chat'
	| 'peer_broadcast'
	| 'other_broadcast'
	| 'group'
	| 'direct_peer_status'
	| 'other_status'
	| 'newsletter'

/**
 * Decode the received node as a message.
 * @note this will only parse the message, not decrypt it
 */
export function decodeMessageNode(stanza: BinaryNode, meId: string, meLid: string) {
	let msgType: MessageType
	let chatId: string
	let author: string

	const msgId = stanza.attrs.id
	const from = stanza.attrs.from
	const participant: string | undefined = stanza.attrs.participant
	const recipient: string | undefined = stanza.attrs.recipient

	const isMe = (jid: string) => areJidsSameUser(jid, meId)
	const isMeLid = (jid: string) => areJidsSameUser(jid, meLid)

	if (isJidUser(from) || isLidUser(from)) {
		if (recipient && !isJidMetaIa(recipient)) {
			if (!isMe(from!) && !isMeLid(from!)) {
				throw new Boom('receipient present, but msg not from me', { data: stanza })
			}

			chatId = recipient
		} else {
			chatId = from!
		}

		msgType = 'chat'
		author = from!
	} else if (isJidGroup(from)) {
		if (!participant) {
			throw new Boom('No participant in group message')
		}

		msgType = 'group'
		author = participant
		chatId = from!
	} else if (isJidBroadcast(from)) {
		if (!participant) {
			throw new Boom('No participant in group message')
		}

		const isParticipantMe = isMe(participant)
		if (isJidStatusBroadcast(from!)) {
			msgType = isParticipantMe ? 'direct_peer_status' : 'other_status'
		} else {
			msgType = isParticipantMe ? 'peer_broadcast' : 'other_broadcast'
		}

		chatId = from!
		author = participant
	} else if (isJidNewsletter(from)) {
		msgType = 'newsletter'
		chatId = from!
		author = from!
	} else {
		throw new Boom('Unknown message type', { data: stanza })
	}

	const fromMe = (isLidUser(from) ? isMeLid : isMe)((stanza.attrs.participant || stanza.attrs.from)!)
	const pushname = stanza?.attrs?.notify

	const key: WAMessageKey = {
		remoteJid: chatId,
		fromMe,
		id: msgId,
		senderLid: stanza?.attrs?.sender_lid || stanza?.attrs?.peer_recipient_lid,
		senderPn: stanza?.attrs?.sender_pn  || stanza?.attrs?.peer_recipient_pn,
		participant,
		participantPn: stanza?.attrs?.participant_pn,
		participantLid: stanza?.attrs?.participant_lid,
		...(msgType === 'newsletter' && stanza.attrs.server_id ? { server_id: stanza.attrs.server_id } : {})
	}

	const fullMessage: WAMessage = {
		key,
		messageTimestamp: +stanza.attrs.t!,
		pushName: pushname,
		broadcast: isJidBroadcast(from)
	}

	if (key.fromMe) {
		fullMessage.status = proto.WebMessageInfo.Status.SERVER_ACK
	}

	return {
		fullMessage,
		author,
		sender: msgType === 'chat' ? author : chatId
	}
}

export const decryptMessageNode = (
	stanza: BinaryNode,
	meId: string,
	meLid: string,
	repository: SignalRepository,
	logger: ILogger
) => {
	const { fullMessage, author, sender } = decodeMessageNode(stanza, meId, meLid)
	return {
		fullMessage,
		category: stanza.attrs.category,
		author,
		async decrypt() {
			let decryptables = 0
			if (Array.isArray(stanza.content)) {
				for (const { tag, attrs, content } of stanza.content) {
					if (tag === 'verified_name' && content instanceof Uint8Array) {
						const cert = proto.VerifiedNameCertificate.decode(content)
						const details = proto.VerifiedNameCertificate.Details.decode(cert.details!)
						fullMessage.verifiedBizName = details.verifiedName
					}

					if (tag === 'unavailable' && attrs.type === 'view_once') {
						fullMessage.key.isViewOnce = true
					}

					if (tag !== 'enc' && tag !== 'plaintext') {
						continue
					}

					if (!(content instanceof Uint8Array)) {
						continue
					}

					decryptables += 1

					let msgBuffer: Uint8Array

					try {
						const e2eType = tag === 'plaintext' ? 'plaintext' : attrs.type
						switch (e2eType) {
							case 'skmsg':
								// Apply LID priority to group message author
								const { senderAlt: authorAlt } = extractAddressingContext(stanza, sender, author)
								const { encryptionJid: authorEncryptionJid } = await determineLIDEncryptionJid(
									author,
									authorAlt,
									repository,
									logger,
									meId
								)
								
								msgBuffer = await repository.decryptGroupMessage({
									group: sender,
									authorJid: authorEncryptionJid,
									msg: content
								})
								break
							case 'pkmsg':
							case 'msg':
								// WHATSMEOW PATTERN: Check for LID migration before decryption
								// If sender has migrated to LID, use the LID session instead of PN
								let decryptionJid = sender
								
								// Check if sender is PN but has migrated to LID
								if (sender.includes('@s.whatsapp.net')) {
									try {
										const lidMapping = repository.getLIDMappingStore()
										const normalizedSender = jidNormalizedUser(sender)
										const lidForPN = await lidMapping.getLIDForPN(normalizedSender)
										
										if (lidForPN && lidForPN.includes('@lid')) {
											// Preserve device ID from original sender
											const senderDecoded = jidDecode(sender)
											const deviceId = senderDecoded?.device || 0
											const lidWithDevice = jidEncode(jidDecode(lidForPN)!.user, 'lid', deviceId)
											
											// Check if LID session exists
											const lidSessionExists = await repository.validateSession(lidWithDevice)
											if (lidSessionExists.exists) {
												decryptionJid = lidWithDevice
												logger.debug({ originalSender: sender, migrationTarget: lidWithDevice }, '🔄 Using migrated LID session for decryption')
											} else {
												// LID mapping exists but no session - trigger migration
												logger.info({ sender, lidMapping: lidWithDevice }, '🔄 LID mapping found but no LID session - triggering migration')
												try {
													await repository.migrateSession(sender, lidWithDevice)
													logger.info({ from: sender, to: lidWithDevice }, '🔄 Created LID session via migration during decryption')
													// Now use the newly created LID session
													decryptionJid = lidWithDevice
												} catch (migrationError) {
													logger.warn({ sender, lidWithDevice, error: migrationError }, 'Failed to migrate to LID session - using PN session')
													// Keep using PN session as fallback
												}
											}
										}
									} catch (error) {
										logger.warn({ sender, error }, 'Failed to check LID migration during decryption')
									}
								}
								
								logger.debug({ sender, decryptionJid, type: e2eType }, 'Decrypting message with determined JID')
								
								// DECRYPT with the determined JID (either original or migrated LID)
								msgBuffer = await repository.decryptMessage({
									jid: decryptionJid,
									type: e2eType,
									ciphertext: content
								})
								
								// 2. AFTER SUCCESSFUL DECRYPTION - Handle LID mapping discovery from addressing context
								// Store any new LID mapping discovered from the message envelope
								const { senderAlt } = extractAddressingContext(stanza, sender)
								
								if (senderAlt && isLidUser(senderAlt) && isJidUser(sender) && decryptionJid === sender) {
									// Only store mapping if we decrypted with PN (not already migrated)
									try {
										await repository.storeLIDPNMapping(senderAlt, sender)
										logger.debug({ sender, senderAlt }, 'Stored new LID mapping discovered from message envelope')
										
										// Trigger session migration for the device that sent this message
										const senderDecoded = jidDecode(sender)
										const deviceId = senderDecoded?.device || 0
										const lidWithDevice = jidEncode(jidDecode(senderAlt)!.user, 'lid', deviceId)
										
										try {
											await repository.migrateSession(sender, lidWithDevice)
											logger.info({ from: sender, to: lidWithDevice }, '🔄 Migrated session to LID after discovering mapping from envelope')
										} catch (migrationError) {
											logger.warn({ sender, lidWithDevice, error: migrationError }, 'Failed to migrate session after LID discovery')
										}
									} catch (error) {
										logger.error({ sender, senderAlt, error }, 'Failed to store LID mapping from envelope')
									}
								}
								break
							case 'plaintext':
								msgBuffer = content
								break
							default:
								throw new Error(`Unknown e2e type: ${e2eType}`)
						}

						let msg: proto.IMessage = proto.Message.decode(
							e2eType !== 'plaintext' ? unpadRandomMax16(msgBuffer) : msgBuffer
						)
						msg = msg.deviceSentMessage?.message || msg
						if (msg.senderKeyDistributionMessage) {
							//eslint-disable-next-line max-depth
							try {
								await repository.processSenderKeyDistributionMessage({
									authorJid: author,
									item: msg.senderKeyDistributionMessage
								})
							} catch (err) {
								logger.error({ key: fullMessage.key, err }, 'failed to decrypt message')
							}
						}

						if (fullMessage.message) {
							Object.assign(fullMessage.message, msg)
						} else {
							fullMessage.message = msg
						}
					} catch (err: any) {
						logger.error({ key: fullMessage.key, err }, 'failed to decrypt message')
						fullMessage.messageStubType = proto.WebMessageInfo.StubType.CIPHERTEXT
						fullMessage.messageStubParameters = [err.message]
					}
				}
			}

			// if nothing was found to decrypt
			if (!decryptables) {
				fullMessage.messageStubType = proto.WebMessageInfo.StubType.CIPHERTEXT
				fullMessage.messageStubParameters = [NO_MESSAGE_FOUND_ERROR_TEXT]
			}
		}
	}
}