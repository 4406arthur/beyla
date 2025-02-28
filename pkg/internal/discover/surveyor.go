package discover

import (
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
)

// Surveyor creates known services metrics series for each discovered process
// based on the Survey definition criteria
type Surveyor struct {
	log *slog.Logger
	cfg *beyla.Config
}

func SurveyorProvider(cfg *beyla.Config) pipe.MiddleProvider[[]Event[ebpf.Instrumentable], []otel.SurveyInfo] {
	return func() (pipe.MiddleFunc[[]Event[ebpf.Instrumentable], []otel.SurveyInfo], error) {
		s := Surveyor{
			log: slog.With("component", "discover.Surveyor"),
			cfg: cfg,
		}

		return s.run, nil
	}
}

func (s *Surveyor) run(in <-chan []Event[ebpf.Instrumentable], out chan<- []otel.SurveyInfo) {
	s.log.Debug("starting surveyor node")

	for i := range in {
		var outArr []otel.SurveyInfo
		s.log.Debug("surveyed new processes", "len", len(i))
		for _, ins := range i {
			s.log.Debug("surveyed process", "cmd", ins.Obj.FileInfo.CmdExePath)
			outArr = append(outArr, otel.SurveyInfo{
				Type: otel.SurveyEventType(ins.Type),
				File: ins.Obj.FileInfo,
			})
		}
		out <- outArr
	}
}
