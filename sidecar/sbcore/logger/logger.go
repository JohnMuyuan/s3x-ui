// Package logger writes sidecar logs to stderr; the panel captures them.
package logger

import (
	"fmt"
	"log"
	"os"
)

var std = log.New(os.Stderr, "", log.LstdFlags)

func Debug(v ...any)   { std.Print("[Debug] " + fmt.Sprint(v...)) }
func Info(v ...any)    { std.Print("[Info] " + fmt.Sprint(v...)) }
func Warning(v ...any) { std.Print("[Warning] " + fmt.Sprint(v...)) }
func Error(v ...any)   { std.Print("[Error] " + fmt.Sprint(v...)) }

func Infof(format string, v ...any)  { Info(fmt.Sprintf(format, v...)) }
func Errorf(format string, v ...any) { Error(fmt.Sprintf(format, v...)) }
