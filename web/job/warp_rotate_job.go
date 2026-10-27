package job

import "x-ui/web/service"

// WarpRotateJob gives WARP a new exit address at the interval set in the
// WARP window.
type WarpRotateJob struct {
	warpService service.WarpService
}

func NewWarpRotateJob() *WarpRotateJob {
	return new(WarpRotateJob)
}

func (j *WarpRotateJob) Run() {
	j.warpService.RotateDue()
}
