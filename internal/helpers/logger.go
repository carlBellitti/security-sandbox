package helpers

import (
	"fmt"
	"time"
)

type Logger struct {
	LoggingEnabled bool
	StartTime      time.Time
}

func InitializeLogger(loggingEnabled bool) Logger {
	return Logger{LoggingEnabled: loggingEnabled, StartTime: time.Now()}
}

func (L *Logger) Log(msg string) {
	if L.LoggingEnabled {
		elapsedTime := time.Since(L.StartTime)
		fmt.Println(msg + "------ elapsed time:" + elapsedTime.String())
	}
}
