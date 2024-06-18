package dtos

import "time"

type ApproveReqDto struct {
	EndDate time.Time `bson:"endDate" json:"endDate"`
}
