import { jidDecode, jidEncode, type JidWithDevice } from '../WABinary'
import { USyncQuery } from '../WAUSync'
import { USyncUser } from '../WAUSync/USyncUser'
import { extractLIDDeviceJids } from './signal'

export type LIDDeviceEnumerationResult = {
	devices: JidWithDevice[]
	success: boolean
	error?: string
}

/**
 * Enumerate LID devices using server-side USyncQuery with LID device protocol
 * Following whatsmeow's approach for proper LID device discovery
 */
export const enumerateLIDDevices = async (
	lidJids: string[],
	myLid: string,
	ignoreZeroDevices: boolean,
	executeUSyncQuery: (query: USyncQuery) => Promise<any>
): Promise<LIDDeviceEnumerationResult> => {
	try {
		if (!lidJids.length) {
			return { devices: [], success: true }
		}

		// Filter to only actual LID addresses
		const actualLidJids = lidJids.filter(jid => jid.includes('@lid'))
		
		if (!actualLidJids.length) {
			return { devices: [], success: true }
		}

		// Create USyncQuery with LID device protocol
		const query = new USyncQuery()
			.withContext('message')
			.withLIDDeviceProtocol()

		// Add each LID user to the query
		for (const lidJid of actualLidJids) {
			const decoded = jidDecode(lidJid)
			if (decoded?.user) {
				// For LID device enumeration, we query the user-level LID
				const userLidJid = jidEncode(decoded.user, 'lid', undefined)
				query.withUser(new USyncUser().withId(userLidJid))
			}
		}

		// Execute the query
		const result = await executeUSyncQuery(query)
		
		if (!result?.list) {
			return { 
				devices: [], 
				success: false, 
				error: 'No result from LID device enumeration query' 
			}
		}

		// Extract LID devices from the result
		const extractedDevices = extractLIDDeviceJids(result.list, myLid, ignoreZeroDevices)
		
		return {
			devices: extractedDevices,
			success: true
		}
	} catch (error) {
		return {
			devices: [],
			success: false,
			error: error instanceof Error ? error.message : 'Unknown error during LID device enumeration'
		}
	}
}

/**
 * Check if LID device enumeration is available and should be used
 * Based on server capabilities and LID address format
 */
export const shouldUseLIDDeviceEnumeration = (jid: string): boolean => {
	// Only use for actual LID addresses that are user-level (not explicit device JIDs)
	if (!jid.includes('@lid')) {
		return false
	}
	
	const decoded = jidDecode(jid)
	// Use LID enumeration for user-level LID addresses (device is undefined or 0)
	return decoded?.device === undefined || decoded.device === 0
}

/**
 * Fallback to device 0 for LID addresses when server enumeration fails
 * This preserves the existing behavior while attempting server enumeration first
 */
export const createLIDDeviceFallback = (lidJid: string): JidWithDevice[] => {
	const decoded = jidDecode(lidJid)
	if (!decoded?.user || !lidJid.includes('@lid')) {
		return []
	}
	
	return [{
		user: decoded.user,
		device: 0
	}]
}