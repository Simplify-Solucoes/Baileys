import type { Contact } from '../../Types'
import { DEFAULT_STATUS_PRIVACY, getStatusRecipients, getStatusSettingMeta } from '../../Utils/status-privacy'

describe('getStatusRecipients', () => {
	it('returns whitelist entries without adding self', () => {
		const recipients = getStatusRecipients({
			contacts: [],
			privacy: {
				type: 'whitelist',
				list: ['5511999999999@s.whatsapp.net']
			}
		})

		expect(recipients).toEqual(['5511999999999@s.whatsapp.net'])
	})

	it('uses all stored non-group contacts for contacts mode', () => {
		const contacts: Contact[] = [
			{ id: '5511999999999@s.whatsapp.net', name: 'Alice' },
			{ id: '5511777777777@s.whatsapp.net', notify: 'Bob' },
			{ id: '123456789@g.us', name: 'Group Chat' },
			{ id: '123456789@lid', phoneNumber: '5511666666666@s.whatsapp.net', name: 'Carol' }
		]

		const recipients = getStatusRecipients({
			contacts,
			privacy: DEFAULT_STATUS_PRIVACY
		})

		expect(recipients).toEqual([
			'5511999999999@s.whatsapp.net',
			'5511777777777@s.whatsapp.net',
			'123456789@lid'
		])
	})

	it('keeps contacts regardless of extra metadata flags', () => {
		const contacts: Contact[] = [
			{ id: '5511999999999@s.whatsapp.net', name: 'Alice' },
			{ id: '5511777777777@s.whatsapp.net' }
		]

		const recipients = getStatusRecipients({
			contacts,
			privacy: DEFAULT_STATUS_PRIVACY
		})

		expect(recipients).toEqual(['5511999999999@s.whatsapp.net', '5511777777777@s.whatsapp.net'])
	})

	it('filters blacklisted contacts using normalized recipient jids', () => {
		const contacts: Contact[] = [
			{ id: '123456789@lid', phoneNumber: '5511999999999@s.whatsapp.net', name: 'Alice' },
			{ id: '5511777777777@s.whatsapp.net', name: 'Bob' }
		]

		const recipients = getStatusRecipients({
			contacts,
			privacy: {
				type: 'blacklist',
				list: ['5511999999999@s.whatsapp.net']
			}
		})

		expect(recipients).toEqual(['5511777777777@s.whatsapp.net'])
	})

	it('falls back to empty audience for unsupported privacy types', () => {
		const recipients = getStatusRecipients({
			contacts: [{ id: '5511999999999@s.whatsapp.net', name: 'Alice' }],
			privacy: {
				type: 'none',
				list: []
			}
		})

		expect(recipients).toEqual([])
	})

	it('maps status modes to the wire status_setting values', () => {
		expect(getStatusSettingMeta('contacts')).toBe('contacts')
		expect(getStatusSettingMeta('blacklist')).toBe('denylist')
		expect(getStatusSettingMeta('whitelist')).toBe('allowlist')
	})
})
