package discover

import (
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
)

// Surveyor creates known services metrics series for each discovered process
// based on the Survey definition criteria
type Surveyor struct {
	log *slog.Logger
	cfg *beyla.Config
}

func SurveyorProvider(cfg *beyla.Config) pipe.FinalProvider[[]Event[ebpf.Instrumentable]] {
	return func() (pipe.FinalFunc[[]Event[ebpf.Instrumentable]], error) {
		s := Surveyor{
			log: slog.With("component", "discover.Surveyor"),
			cfg: cfg,
		}

		return s.run, nil
	}
}

func (s *Surveyor) run(in <-chan []Event[ebpf.Instrumentable]) {
	s.log.Debug("starting criteria matcher node")
	for i := range in {
		s.log.Debug("surveyed new processes", "len", len(i))
		for _, ins := range i {
			s.log.Info("surveyed process", "cmd", ins.Obj.FileInfo.CmdExePath)
		}
	}
}
