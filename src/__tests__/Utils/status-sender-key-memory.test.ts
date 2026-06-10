import {
	getStatusSenderKeyMemoryKey,
	markSenderKeyDistributionSent,
	planSenderKeyDistribution
} from '../../Utils/status-sender-key-memory'

describe('status sender-key memory', () => {
	const devices = [
		{ jid: '111@lid', user: '111', device: 0 },
		{ jid: '111:1@lid', user: '111', device: 1 },
		{ jid: '222@lid', user: '222', device: 0 }
	]

	it('uses a sender-scoped status memory key', () => {
		expect(getStatusSenderKeyMemoryKey('status@broadcast', '999:1@lid')).toBe('status@broadcast:999@lid')
	})

	it('sends sender-key distribution to every deliverable device when memory is empty', () => {
		const plan = planSenderKeyDistribution({
			devices,
			includeReusedUserParticipantNodes: true,
			resetOnUnmatchedMemory: true,
			senderKeyMap: {}
		})

		expect(plan.senderKeyRecipients).toEqual(['111@lid', '111:1@lid', '222@lid'])
		expect(plan.participantNodes).toEqual([])
		expect(plan.nextSenderKeyMap).toEqual({})
		expect(plan.shouldResetSenderKeyMemory).toBe(false)
	})

	it('reuses remembered status devices and adds user participant nodes for fanout', () => {
		const plan = planSenderKeyDistribution({
			devices,
			includeReusedUserParticipantNodes: true,
			resetOnUnmatchedMemory: true,
			senderKeyMap: {
				'111@lid': true,
				'111:1@lid': true,
				'222@lid': true
			}
		})

		expect(plan.senderKeyRecipients).toEqual([])
		expect(plan.participantNodes).toEqual([
			{ tag: 'to', attrs: { jid: '111@lid' } },
			{ tag: 'to', attrs: { jid: '222@lid' } }
		])
		expect(plan.nextSenderKeyMap).toEqual({
			'111@lid': true,
			'111:1@lid': true,
			'222@lid': true
		})
	})

	it('adds status fanout participant nodes only from remembered primary devices', () => {
		const plan = planSenderKeyDistribution({
			devices,
			includeReusedUserParticipantNodes: true,
			resetOnUnmatchedMemory: true,
			senderKeyMap: {
				'111:1@lid': true
			}
		})

		expect(plan.senderKeyRecipients).toEqual(['111@lid', '222@lid'])
		expect(plan.participantNodes).toEqual([])
		expect(plan.nextSenderKeyMap).toEqual({
			'111:1@lid': true
		})
	})

	it('resets status memory when remembered devices are outside the current audience', () => {
		const plan = planSenderKeyDistribution({
			devices: devices.slice(0, 2),
			includeReusedUserParticipantNodes: true,
			resetOnUnmatchedMemory: true,
			senderKeyMap: {
				'111@lid': true,
				'111:1@lid': true,
				'222@lid': true
			}
		})

		expect(plan.shouldResetSenderKeyMemory).toBe(true)
		expect(plan.senderKeyRecipients).toEqual(['111@lid', '111:1@lid'])
		expect(plan.participantNodes).toEqual([])
		expect(plan.nextSenderKeyMap).toEqual({})
	})

	it('filters hosted and device 99 sender-key targets', () => {
		const plan = planSenderKeyDistribution({
			devices: [
				{ jid: '111@lid', device: 0 },
				{ jid: '222@hosted.lid', device: 0 },
				{ jid: '333@hosted', device: 0 },
				{ jid: '444:99@lid', device: 99 }
			],
			senderKeyMap: {}
		})

		expect(plan.senderKeyRecipients).toEqual(['111@lid'])
	})

	it('marks only successfully encrypted sender-key distribution nodes as remembered', () => {
		const next = markSenderKeyDistributionSent({ '111@lid': true }, [
			{ tag: 'to', attrs: { jid: '222@lid' } },
			{ tag: 'to', attrs: {} }
		])

		expect(next).toEqual({
			'111@lid': true,
			'222@lid': true
		})
	})
})
