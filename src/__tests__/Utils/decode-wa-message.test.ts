import { Boom } from '@hapi/boom'
import { jest } from '@jest/globals'
import type { SignalRepositoryWithLIDStore } from '../../Types/Signal'
import { decodeMessageNode, decryptMessageNode } from '../../Utils/decode-wa-message'
import type { ILogger } from '../../Utils/logger'
import { StaleSocketTaskError } from '../../Utils/socket-task-guard'
import type { BinaryNode } from '../../WABinary'

const ME_ID = '5511999999999@s.whatsapp.net'
const ME_LID = '111111111111111@lid'
const PEER_ID = '5511888888888@s.whatsapp.net'
const GROUP_ID = '120363000000000000@g.us'

const message = (attrs: Record<string, string>): BinaryNode => ({
	tag: 'message',
	attrs: { t: '1700000000', ...attrs },
	content: []
})

const captureThrow = (fn: () => unknown): unknown => {
	try {
		fn()
	} catch (err) {
		return err
	}

	throw new Error('expected function to throw')
}

const makeTestLogger = (): ILogger =>
	({
		level: 'silent',
		child: () => makeTestLogger(),
		trace: jest.fn(),
		debug: jest.fn(),
		info: jest.fn(),
		warn: jest.fn(),
		error: jest.fn(),
		fatal: jest.fn()
	}) as unknown as ILogger

describe('decodeMessageNode', () => {
	describe('validation', () => {
		it('throws Boom when stanza has no id attribute', () => {
			const stanza = message({ from: PEER_ID })
			const err = captureThrow(() => decodeMessageNode(stanza, ME_ID, ME_LID))
			expect(err).toBeInstanceOf(Boom)
			expect((err as Error).message).toMatch(/missing id/)
		})

		it('throws Boom when stanza has no from attribute', () => {
			const stanza = message({ id: 'MSG_1' })
			const err = captureThrow(() => decodeMessageNode(stanza, ME_ID, ME_LID))
			expect(err).toBeInstanceOf(Boom)
			expect((err as Error).message).toMatch(/missing from/)
		})

		it('throws Boom for an unknown jid type', () => {
			const stanza = message({ id: 'MSG_1', from: 'unknown@server' })
			expect(() => decodeMessageNode(stanza, ME_ID, ME_LID)).toThrow(/Unknown message type/)
		})

		it('throws Boom for group message without participant', () => {
			const stanza = message({ id: 'MSG_1', from: GROUP_ID })
			expect(() => decodeMessageNode(stanza, ME_ID, ME_LID)).toThrow(/No participant/)
		})
	})

	describe('happy paths', () => {
		it('decodes a 1:1 incoming chat message', () => {
			const stanza = message({ id: 'MSG_1', from: PEER_ID })
			const result = decodeMessageNode(stanza, ME_ID, ME_LID)

			expect(result.fullMessage.key.id).toBe('MSG_1')
			expect(result.fullMessage.key.remoteJid).toBe(PEER_ID)
			expect(result.fullMessage.key.fromMe).toBeFalsy()
			expect(result.author).toBe(PEER_ID)
		})

		it('decodes an outgoing chat message (recipient set, from = me)', () => {
			const stanza = message({ id: 'MSG_2', from: ME_ID, recipient: PEER_ID })
			const result = decodeMessageNode(stanza, ME_ID, ME_LID)

			expect(result.fullMessage.key.fromMe).toBe(true)
			expect(result.fullMessage.key.remoteJid).toBe(PEER_ID)
		})

		it('rejects a recipient-tagged message that is not from me', () => {
			const stanza = message({ id: 'MSG_3', from: PEER_ID, recipient: ME_ID })
			expect(() => decodeMessageNode(stanza, ME_ID, ME_LID)).toThrow(/not from me/)
		})

		it('decodes a group message', () => {
			const stanza = message({ id: 'MSG_G', from: GROUP_ID, participant: PEER_ID })
			const result = decodeMessageNode(stanza, ME_ID, ME_LID)

			expect(result.fullMessage.key.remoteJid).toBe(GROUP_ID)
			expect(result.fullMessage.key.participant).toBe(PEER_ID)
			expect(result.author).toBe(PEER_ID)
		})
	})

	describe('socket generation fencing', () => {
		it('does not turn an inactive-generation error into a ciphertext placeholder', async () => {
			const staleError = new StaleSocketTaskError()
			const repository = {
				lidMapping: {
					getLIDForPN: jest.fn<() => Promise<undefined>>().mockResolvedValue(undefined)
				},
				decryptMessage: jest.fn<() => Promise<Uint8Array>>().mockRejectedValue(staleError)
			} as unknown as SignalRepositoryWithLIDStore
			const stanza: BinaryNode = {
				tag: 'message',
				attrs: { id: 'MSG_STALE', from: PEER_ID, t: '1700000000' },
				content: [{ tag: 'enc', attrs: { type: 'msg' }, content: new Uint8Array([1]) }]
			}
			const logger = makeTestLogger()
			const result = decryptMessageNode(stanza, ME_ID, ME_LID, repository, logger)

			await expect(result.decrypt()).rejects.toBe(staleError)
			expect(result.fullMessage.messageStubType).toBeUndefined()
			expect(logger.error).not.toHaveBeenCalled()
		})
	})
})
