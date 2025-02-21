package task

import (
	"time"

	lModel "dkhalife.com/tasks/core/internal/models/label"
	nModel "dkhalife.com/tasks/core/internal/models/notifier"
	"github.com/lib/pq"
)

type FrequencyType string

const (
	RepeatOnce    = "once"
	RepeatDaily   = "daily"
	RepeatWeekly  = "weekly"
	RepeatMonthly = "monthly"
	RepeatYearly  = "yearly"
	RepeatCustom  = "custom"
)

type IntervalUnit string

const (
	Hours  IntervalUnit = "hours"
	Days   IntervalUnit = "days"
	Weeks  IntervalUnit = "weeks"
	Months IntervalUnit = "months"
	Years  IntervalUnit = "years"
)

type RepeatOn string

const (
	Interval       RepeatOn = "interval"
	DaysOfTheWeek  RepeatOn = "days_of_the_week"
	DayOfTheMonths RepeatOn = "day_of_the_months"
)

type Frequency struct {
	Type   FrequencyType `json:"type" validate:"required" gorm:"type:varchar(9)"`
	On     RepeatOn      `json:"on" validate:"required_if=Type interval custom" gorm:"type:varchar(18);default:null"`
	Every  int           `json:"every" validate:"required_if=On interval" gorm:"type:int;default:null"`
	Unit   IntervalUnit  `json:"unit" validate:"required_if=On interval" gorm:"type:varchar(9);default:null"`
	Days   pq.Int32Array `json:"days" validate:"required_if=Type custom On days_of_the_week,dive,gte=0,lte=6" gorm:"type:integer[];default:null"`
	Months pq.Int32Array `json:"months" validate:"required_if=Type custom On day_of_the_months,dive,gte=0,lte=11" gorm:"type:integer[];default:null"`
}

type Task struct {
	ID           int                               `json:"id" gorm:"primary_key"`
	Title        string                            `json:"title" gorm:"column:title"`
	Frequency    Frequency                         `json:"frequency" gorm:"embedded;embeddedPrefix:frequency_"`
	NextDueDate  *time.Time                        `json:"next_due_date" gorm:"column:next_due_date;index"`
	IsRolling    bool                              `json:"is_rolling" gorm:"column:is_rolling"`
	CreatedBy    int                               `json:"created_by" gorm:"column:created_by"`
	IsActive     bool                              `json:"is_active" gorm:"column:is_active"`
	Notification nModel.NotificationTriggerOptions `json:"notification" gorm:"embedded;embeddedPrefix:notification_"`
	CreatedAt    time.Time                         `json:"created_at" gorm:"column:created_at"`
	UpdatedAt    time.Time                         `json:"updated_at" gorm:"column:updated_at"`
	Labels       []lModel.Label                    `json:"labels" gorm:"many2many:task_labels;"`
}

type TaskHistory struct {
	ID            int        `json:"id" gorm:"primary_key"`
	TaskID        int        `json:"task_id" gorm:"column:task_id"`
	CompletedDate *time.Time `json:"completed_date" gorm:"column:completed_date"`
	DueDate       *time.Time `json:"due_date" gorm:"column:due_date"`
}

type TaskLabels struct {
	TaskID  int `json:"task_id"`
	LabelID int `json:"label_id"`
}
