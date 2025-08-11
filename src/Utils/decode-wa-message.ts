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
	jidDecode
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
								const { addressingMode: groupAddressingMode, senderAlt: authorAlt } = extractAddressingContext(stanza, sender, author)
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
								// WHATSMEOW EXACT: Simple LID priority system (message.go:948-961)
								const { addressingMode, senderAlt } = extractAddressingContext(stanza, sender)
								let senderEncryptionJid = sender
								
								// Store LID mapping when detected from message metadata
								if (senderAlt && isLidUser(senderAlt) && isJidUser(sender)) {
									try {
										await repository.storeLIDPNMapping(senderAlt, sender)
										logger.debug({ sender, senderAlt }, 'Stored LID mapping from message metadata')
									} catch (error) {
										logger.error({ sender, senderAlt, error }, 'Failed to store LID mapping from metadata')
									}
								}
								
								// WHATSMEOW EXACT: LID priority logic (message.go:949-961)
								// CRITICAL FIX: Don't migrate during decryption - prefer existing LID sessions
								if (isJidUser(sender) && !sender.includes('bot')) {
									if (senderAlt && isLidUser(senderAlt)) {
										// PRIORITY 1: Use LID from message metadata (exact whatsmeow pattern)
										senderEncryptionJid = senderAlt
										logger.debug({ sender, senderAlt }, 'Using LID from message metadata for decryption')
									} else {
										// PRIORITY 2: Check for existing LID sessions (whatsmeow LID priority)
										try {
											const lidStore = repository.getLIDMappingStore()
											const storedLid = await lidStore.getLIDForPN(sender)
											
											if (storedLid) {
												// Check if LID session exists - if so, use it (avoid migration during decryption)
												const { exists: hasLIDSession } = await repository.validateSession(storedLid)
												
												if (hasLIDSession) {
													senderEncryptionJid = storedLid
													logger.info({ sender, storedLid }, '✅ Using existing LID session for decryption (LID priority)')
												} else {
													// No LID session exists - migrate during decryption as fallback
													logger.warn({ sender, storedLid }, '⚠️ LID mapping exists but no LID session - migrating during decryption')
													await repository.migrateSession(sender, storedLid)
													senderEncryptionJid = storedLid
												}
											} else {
												logger.debug({ sender }, 'No LID mapping found for PN sender')
											}
										} catch (lidError: any) {
											logger.error({ sender, error: lidError.message }, 'Failed to check LID mapping during decryption')
										}
									}
								}
								
								logger.debug({ 
									originalSender: sender,
									finalSender: senderEncryptionJid,
									addressingMode
								}, 'WHATSMEOW: Determined encryption JID for decryption')
								
								// WHATSMEOW APPROACH: Trust the determined encryption JID, no fallback
								msgBuffer = await repository.decryptMessage({
									jid: senderEncryptionJid,
									type: e2eType,
									ciphertext: content
								})
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
