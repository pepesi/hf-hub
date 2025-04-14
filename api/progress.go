package api

import (
	"io"

	"github.com/schollz/progressbar/v3"
)

type Progress interface {
	Set64(total int64) error
	io.Writer
}

type wrapperProgressBar struct {
	*progressbar.ProgressBar
}

func (p *wrapperProgressBar) Set64(total int64) error {
	return p.ProgressBar.Set64(total)
}
func (p *wrapperProgressBar) Write(bs []byte) (int, error) {
	return p.ProgressBar.Write(bs)
}

var _ Progress = &wrapperProgressBar{}

type TotalProgress struct {
	Total   int64
	Current int64
}

func (p *TotalProgress) Set64(total int64) error {
	p.Total = total
	return nil
}

func (p *TotalProgress) Write(bs []byte) (int, error) {
	p.Current += int64(len(bs))
	return len(bs), nil
}

var _ Progress = &TotalProgress{}
