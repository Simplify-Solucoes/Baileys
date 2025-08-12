import type { USyncQueryProtocol } from '../../Types/USync'
import { assertNodeErrorFree, type BinaryNode, getBinaryNodeChild } from '../../WABinary'

export type LIDDeviceData = {
	id: number
	keyIndex?: number
	isHosted?: boolean
}

export type LIDKeyIndexData = {
	timestamp: number
	signedKeyIndex?: Uint8Array
	expectedTimestamp?: number
}

export type ParsedLIDDeviceInfo = {
	deviceList?: LIDDeviceData[]
	keyIndex?: LIDKeyIndexData
}

/**
 * LID Device Protocol for server-side LID device enumeration
 * Following whatsmeow's approach for LID device discovery
 */
export class USyncLIDDeviceProtocol implements USyncQueryProtocol {
	name = 'lid_devices'

	getQueryElement(): BinaryNode {
		return {
			tag: 'lid_devices',
			attrs: {
				version: '2'
			}
		}
	}

	getUserElement(): BinaryNode | null {
		// For LID device queries, we don't need user-specific elements
		// The server handles LID device enumeration differently than PN devices
		return null
	}

	parser(node: BinaryNode): ParsedLIDDeviceInfo {
		const deviceList: LIDDeviceData[] = []
		let keyIndex: LIDKeyIndexData | undefined = undefined

		if (node.tag === 'lid_devices') {
			assertNodeErrorFree(node)
			const deviceListNode = getBinaryNodeChild(node, 'device-list')
			const keyIndexNode = getBinaryNodeChild(node, 'key-index-list')

			if (Array.isArray(deviceListNode?.content)) {
				for (const { tag, attrs } of deviceListNode.content) {
					const id = +attrs.id!
					const keyIndex = +attrs['key-index']!
					if (tag === 'device') {
						deviceList.push({
							id,
							keyIndex,
							isHosted: !!(attrs['is_hosted'] && attrs['is_hosted'] === 'true')
						})
					}
				}
			}

			if (keyIndexNode?.tag === 'key-index-list') {
				keyIndex = {
					timestamp: +keyIndexNode.attrs['ts']!,
					signedKeyIndex: keyIndexNode?.content as Uint8Array,
					expectedTimestamp: keyIndexNode.attrs['expected_ts'] ? +keyIndexNode.attrs['expected_ts'] : undefined
				}
			}
		}

		return {
			deviceList,
			keyIndex
		}
	}
}