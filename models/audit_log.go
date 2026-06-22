package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog records who did what to which resource. It is written through the
// audit service, the single chokepoint for audit entries. The shape mirrors a
// future event payload so audit can move to an event/queue pipeline later
// without changing callers.
type AuditLog struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	ActorID      *uuid.UUID `gorm:"type:uuid;index" json:"actor_id,omitempty"`
	ActorEmail   string     `gorm:"type:varchar(255)" json:"actor_email,omitempty"`
	Action       string     `gorm:"type:varchar(255);not null" json:"action"`
	ResourceType string     `gorm:"type:varchar(255)" json:"resource_type,omitempty"`
	ResourceID   *string    `gorm:"type:varchar(255)" json:"resource_id,omitempty"`
	Metadata     JSONMap    `gorm:"type:jsonb" json:"metadata,omitempty"`
	IP           string     `gorm:"type:varchar(64)" json:"ip,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
