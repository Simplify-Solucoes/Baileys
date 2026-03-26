import type { Contact } from '../Types'
import { isHostedLidUser, isHostedPnUser, isLidUser, isPnUser, jidNormalizedUser } from '../WABinary'

export type StatusPrivacyType = 'contacts' | 'blacklist' | 'whitelist'
export type StatusSettingMeta = 'contacts' | 'denylist' | 'allowlist'

export type StatusPrivacySetting = {
	type: StatusPrivacyType | string
	list: string[]
	isDefault?: boolean
}

export const DEFAULT_STATUS_PRIVACY: StatusPrivacySetting = {
	type: 'contacts',
	list: [],
	isDefault: true
}

const uniqueJids = (jids: Array<string | undefined>) =>
	Array.from(new Set(jids.filter((jid): jid is string => !!jid).map(jid => jidNormalizedUser(jid))))

const isUserJid = (jid: string | undefined) =>
	isPnUser(jid) || isLidUser(jid) || isHostedPnUser(jid) || isHostedLidUser(jid)

const getPreferredStatusJid = (contact: Contact) => {
	for (const candidate of [contact.lid, contact.id, contact.phoneNumber]) {
		if (!candidate) {
			continue
		}

		const normalized = jidNormalizedUser(candidate)
		if (normalized && isUserJid(normalized)) {
			return normalized
		}
	}
}

const getContactVariants = (contact: Contact) =>
	uniqueJids([contact.id, contact.lid, contact.phoneNumber])

export const getStatusSettingMeta = (type: StatusPrivacySetting['type']): StatusSettingMeta => {
	switch (type) {
		case 'whitelist':
			return 'allowlist'
		case 'blacklist':
			return 'denylist'
		case 'contacts':
		default:
			return 'contacts'
	}
}

export const getStatusRecipients = ({
	contacts,
	privacy
}: {
	contacts: Contact[]
	privacy: StatusPrivacySetting
}) => {
	if (privacy.type === 'whitelist') {
		return uniqueJids(privacy.list)
	}

	if (privacy.type !== 'contacts' && privacy.type !== 'blacklist') {
		return []
	}

	const blacklist = new Set(privacy.type === 'blacklist' ? uniqueJids(privacy.list) : [])
	const recipients = contacts
		.filter(contact => {
			if (blacklist.size === 0) {
				return true
			}

			return !getContactVariants(contact).some(jid => blacklist.has(jid))
		})
		.map(getPreferredStatusJid)
		.filter((jid): jid is string => !!jid)

	return uniqueJids(recipients)
}
