import type { SignalDataTypeMap } from '../Types'
import { type BinaryNode, isHostedLidUser, isHostedPnUser, jidNormalizedUser, type JidWithDevice } from '../WABinary'

export type SenderKeyMemoryMap = SignalDataTypeMap['sender-key-memory']

type SenderKeyMemoryDevice = Pick<JidWithDevice, 'device'> & {
	jid: string
}

export type SenderKeyDistributionPlan = {
	participantNodes: BinaryNode[]
	reusedDeviceJids: string[]
	senderKeyRecipients: string[]
	shouldResetSenderKeyMemory: boolean
	nextSenderKeyMap: SenderKeyMemoryMap
}

export const getStatusSenderKeyMemoryKey = (statusJid: string, senderJid: string) => {
	const sender = jidNormalizedUser(senderJid)
	return sender ? `${statusJid}:${sender}` : statusJid
}

export const isSenderKeyMemoryDevice = (device: SenderKeyMemoryDevice) =>
	!!device.jid && !isHostedLidUser(device.jid) && !isHostedPnUser(device.jid) && device.device !== 99

const isPrimarySenderKeyMemoryDevice = (device: SenderKeyMemoryDevice) =>
	device.device === undefined || device.device === 0

export const planSenderKeyDistribution = ({
	devices,
	includeReusedUserParticipantNodes = false,
	resetOnUnmatchedMemory = false,
	senderKeyMap
}: {
	devices: SenderKeyMemoryDevice[]
	includeReusedUserParticipantNodes?: boolean
	resetOnUnmatchedMemory?: boolean
	senderKeyMap: SenderKeyMemoryMap
}): SenderKeyDistributionPlan => {
	const deliverableDevices = devices.filter(isSenderKeyMemoryDevice)
	const currentDeviceJids = new Set(deliverableDevices.map(device => device.jid))
	const rememberedDeviceJids = Object.keys(senderKeyMap).filter(jid => senderKeyMap[jid])
	const shouldResetSenderKeyMemory =
		resetOnUnmatchedMemory && rememberedDeviceJids.some(jid => !currentDeviceJids.has(jid))
	const effectiveSenderKeyMap = shouldResetSenderKeyMemory ? {} : senderKeyMap

	const nextSenderKeyMap: SenderKeyMemoryMap = {}
	const participantUserJids = new Set<string>()
	const reusedDeviceJids: string[] = []
	const senderKeyRecipients: string[] = []
	const seenDeviceJids = new Set<string>()

	for (const device of deliverableDevices) {
		const deviceJid = device.jid
		if (seenDeviceJids.has(deviceJid)) {
			continue
		}

		seenDeviceJids.add(deviceJid)
		if (effectiveSenderKeyMap[deviceJid]) {
			nextSenderKeyMap[deviceJid] = true
			reusedDeviceJids.push(deviceJid)

			if (includeReusedUserParticipantNodes && isPrimarySenderKeyMemoryDevice(device)) {
				const userJid = jidNormalizedUser(deviceJid)
				if (userJid) {
					participantUserJids.add(userJid)
				}
			}
		} else {
			senderKeyRecipients.push(deviceJid)
		}
	}

	return {
		nextSenderKeyMap,
		participantNodes: Array.from(participantUserJids).map(jid => ({
			tag: 'to',
			attrs: { jid }
		})),
		reusedDeviceJids,
		senderKeyRecipients,
		shouldResetSenderKeyMemory
	}
}

export const markSenderKeyDistributionSent = (
	senderKeyMap: SenderKeyMemoryMap,
	participantNodes: BinaryNode[]
): SenderKeyMemoryMap => {
	const nextSenderKeyMap: SenderKeyMemoryMap = { ...senderKeyMap }
	for (const node of participantNodes) {
		const jid = node.attrs.jid
		if (jid) {
			nextSenderKeyMap[jid] = true
		}
	}

	return nextSenderKeyMap
}
