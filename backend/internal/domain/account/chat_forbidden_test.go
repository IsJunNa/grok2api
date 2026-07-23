package account

import (
	"strings"
	"testing"
	"time"
)

func TestChatForbiddenMarkers(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	until := now.Add(24 * time.Hour)
	past := now.Add(-time.Minute)

	if !IsChatForbiddenSuspend("403:anti-bot") {
		t.Fatal("suspend marker")
	}
	if IsChatForbiddenSuspend("403-disabled:anti-bot") {
		t.Fatal("disabled must not match suspend")
	}
	if !IsChatForbiddenDisabled("403-disabled:anti-bot") {
		t.Fatal("disabled marker")
	}
	if !IsActiveChatForbiddenCooldown("403:x", &until, now) {
		t.Fatal("active cooldown")
	}
	if IsActiveChatForbiddenCooldown("403:x", &past, now) {
		t.Fatal("expired cooldown")
	}
	if !IsRecoveredChatForbiddenProbe("403:x", &past, now) {
		t.Fatal("recovered probe")
	}
	if IsRecoveredChatForbiddenProbe("403:x", &until, now) {
		t.Fatal("active should not be recovered probe")
	}
	if IsRecoveredChatForbiddenProbe("403-disabled:x", &past, now) {
		t.Fatal("disabled is not recovered probe")
	}
	if ChatForbiddenHitCount("403:hits=3:anti-bot") != 3 {
		t.Fatal("hit count parse")
	}
	if ChatForbiddenHitCount("403:legacy") != 1 {
		t.Fatal("legacy hit count")
	}
	if !strings.HasPrefix(FormatChatForbiddenSuspend(2, "x"), "403:hits=2:") {
		t.Fatal("format suspend")
	}
}
