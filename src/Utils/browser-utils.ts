import { platform, release } from 'os'
import { proto } from '../../WAProto/index.js'
import type { BrowsersMap } from '../Types'

const PLATFORM_MAP = {
	aix: 'AIX',
	darwin: 'Mac OS',
	win32: 'Windows',
	android: 'Android',
	freebsd: 'FreeBSD',
	openbsd: 'OpenBSD',
	sunos: 'Solaris',
	linux: undefined,
	haiku: undefined,
	cygwin: undefined,
	netbsd: undefined
}

export const Browsers: BrowsersMap = {
	ubuntu: browser => ['Ubuntu', browser, '22.04.4'],
	macOS: browser => ['Mac OS', browser, '14.4.1'],
	baileys: browser => ['Baileys', browser, '6.5.0'],
	windows: browser => ['Windows', browser, '10.0.22631'],
	android: browser => [browser, 'Android', ''],
	iphone: browser => [browser, 'iPhone', ''],
	/** The appropriate browser based on your OS & release */
	appropriate: browser => [PLATFORM_MAP[platform()] || 'Ubuntu', browser, release()]
}

export const getPlatformId = (browser: string) => {
	const platformType = proto.DeviceProps.PlatformType[browser.toUpperCase() as any]
	return platformType ? platformType.toString() : '1' //chrome
}

export type BrowserInfo = {
	platform: proto.ClientPayload.UserAgent.Platform
	isMobile: boolean
}

export const getBrowserInfo = (browser: string): BrowserInfo => {
	const browserType = browser.toLowerCase()
	if (browserType.includes('android')) {
		return { platform: proto.ClientPayload.UserAgent.Platform.ANDROID, isMobile: true }
	}
	if (browserType.includes('iphone')) {
		return { platform: proto.ClientPayload.UserAgent.Platform.IOS, isMobile: true }
	}
	return { platform: proto.ClientPayload.UserAgent.Platform.WEB, isMobile: false }
}
