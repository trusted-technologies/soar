package l7

// gateAction is the decision for a login attempt after policy checks passed.
type gateAction int

const (
	gatePass gateAction = iota
	// gateChallengeReconnect kicks the player asking them to reconnect; a
	// reconnect inside the verify window marks the address as verified.
	gateChallengeReconnect
	// gateChallengeCaptcha kicks the player with a browser captcha link.
	gateChallengeCaptcha
)

// gate decides whether an unverified login may pass straight through or has
// to be challenged, based on the configured bot detection level and whether
// mitigation (attack mode) is currently active.
//
// The ladder, roughly modeled after MineGuard's detection levels:
//   - off:      never challenge (rate limits and firewall still apply).
//   - low:      challenge only while mitigation is active.
//   - medium:   like low; with extended checks a missing status ping before
//     login during mitigation is treated as suspicious.
//   - high:     always challenge unverified addresses.
//   - paranoid: always challenge; captcha is preferred when available and a
//     status ping before login is required while mitigation is active.
func gate(s Settings, mitigation bool, statusSeen bool, strikes int) gateAction {
	level := s.BotLevel
	if level == BotLevelOff {
		return gatePass
	}

	challenge := false
	switch level {
	case BotLevelLow:
		challenge = mitigation
	case BotLevelMedium:
		challenge = mitigation
		if s.ExtendedChecks && mitigation && !statusSeen {
			challenge = true
		}
	case BotLevelHigh:
		challenge = true
	case BotLevelParanoid:
		challenge = true
	}
	if !challenge {
		return gatePass
	}

	if s.CaptchaEnabled {
		// Prefer the cheap reconnect challenge first and escalate to captcha
		// for addresses that keep tripping the filter. Paranoid goes straight
		// to captcha, as does a missing ping under extended checks.
		if level == BotLevelParanoid {
			return gateChallengeCaptcha
		}
		if strikes >= 2 {
			return gateChallengeCaptcha
		}
		if s.ExtendedChecks && mitigation && !statusSeen {
			return gateChallengeCaptcha
		}
	}
	return gateChallengeReconnect
}
