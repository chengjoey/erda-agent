package rpc

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"

	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	rpcebpf "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/rpc/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
)

const (
	measurementGroup = "application_rpc"
)

var (
	pathRegexp = regexp.MustCompile(`(.*)!([a-zA-Z.]+)([0-9.]+)([a-zA-Z/;]+)`)
)

type provider struct {
	sync.RWMutex
	ch           chan rpcebpf.Metric
	kprobeHelper kprobe.Interface
	rpcProbes    map[int]*rpcebpf.Ebpf
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.rpcProbes = make(map[int]*rpcebpf.Ebpf)
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.ch = make(chan rpcebpf.Metric, 100)
	eBPFprogram := rpcebpf.GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		panic(err)
	}
	vethes, err := p.kprobeHelper.GetVethes()
	if err != nil {
		panic(err)
	}
	for _, veth := range vethes {
		proj := rpcebpf.NewEbpf(veth.Link.Attrs().Index, veth.Neigh.IP.String(), p.ch)
		if err := proj.Load(spec); err != nil {
			log.Fatalf("failed to load ebpf, err: %v", err)
		}
		p.Lock()
		p.rpcProbes[veth.Link.Attrs().Index] = proj
		p.Unlock()
	}
	go p.sendMetrics(c)
	vethEvents := p.kprobeHelper.RegisterNetLinkListener()
	for {
		select {
		case event := <-vethEvents:
			switch event.Type {
			case kprobe.LinkAdd:
				klog.Infof("veth add, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
				p.Lock()
				if _, ok := p.rpcProbes[event.Link.Attrs().Index]; ok {
					p.Unlock()
					continue
				}
				proj := rpcebpf.NewEbpf(event.Link.Attrs().Index, event.Neigh.IP.String(), p.ch)
				if err := proj.Load(spec); err != nil {
					log.Fatalf("failed to load ebpf, err: %v", err)
				}
				p.rpcProbes[event.Link.Attrs().Index] = proj
				p.Unlock()
			case kprobe.LinkDelete:
				klog.Infof("veth delete, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
				p.Lock()
				proj, ok := p.rpcProbes[event.Link.Attrs().Index]
				if ok {
					proj.Close()
					delete(p.rpcProbes, event.Link.Attrs().Index)
				}
				p.Unlock()
			default:
				klog.Infof("unknown event type: %v", event.Type)
			}
		}
	}
}

func (p *provider) sendMetrics(c chan metric.Metric) {
	for {
		select {
		case m := <-p.ch:
			if len(m.Status) == 0 || len(m.Path) == 0 {
				continue
			}
			mc := p.convertRpc2Metric(&m)
			c <- mc
			klog.Infof("rpc metric: %+v", mc)
		}
	}
}

func (p *provider) convertRpc2Metric(m *rpcebpf.Metric) metric.Metric {
	res := metric.Metric{
		Name:        measurementGroup,
		Measurement: measurementGroup,
		Timestamp:   time.Now().UnixNano(),
		Tags:        map[string]string{},
		Fields: map[string]interface{}{
			"elapsed_count": 1,
			"elapsed_sum":   m.Duration,
			"elapsed_max":   m.Duration,
			"elapsed_min":   m.Duration,
			"elapsed_mean":  m.Duration,
		},
	}
	res.Tags["metric_source"] = "ebpf"
	res.Tags["_meta"] = "true"
	res.Tags["_metric_scope"] = "micro_service"
	var rpcTarget, rpcMethod, rpcService, rpcVersion, serviceVersion string
	rpcTarget = m.Path
	parseLine := pathRegexp.FindStringSubmatch(m.Path)
	if len(parseLine) == 5 {
		rpcTarget = fmt.Sprintf("%s.%s", parseLine[2], parseLine[4])
		rpcMethod = parseLine[4]
		rpcService = parseLine[2]
		rpcVersion = parseLine[1]
		serviceVersion = parseLine[3]
	}
	res.Tags["rpc_target"] = rpcTarget
	targetPod, err := p.kprobeHelper.GetPodByUID(m.SrcIP)
	if err == nil {
		res.OrgName = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["cluster_name"] = targetPod.Labels["DICE_CLUSTER_NAME"]
		res.Tags["component"] = string(m.RpcType)
		res.Tags["db_host"] = fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)
		res.Tags["method"] = m.Path
		res.Tags["_metric_scope_id"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		if m.RpcType == rpcebpf.RPC_TYPE_DUBBO {
			res.Tags["dubbo_service"] = rpcService
			res.Tags["dubbo_version"] = rpcVersion
			res.Tags["dubbo_method"] = rpcMethod
			res.Tags["service_version"] = serviceVersion
			if m.Status == "20" {
				res.Tags["error"] = "false"
			} else {
				res.Tags["error"] = "true"
			}
		} else {
			if m.Status == "200" {
				res.Tags["error"] = "false"
			} else {
				res.Tags["error"] = "true"
			}
		}
		res.Tags["host_ip"] = targetPod.Status.HostIP
		res.Tags["org_name"] = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["peer_address"] = fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)
		res.Tags["peer_service"] = m.Path
		res.Tags["rpc_method"] = res.Tags["dubbo_method"]
		res.Tags["rpc_service"] = res.Tags["dubbo_service"]
		res.Tags["span_kind"] = "server"
		res.Tags["target_application_id"] = targetPod.Labels["DICE_APPLICATION_ID"]
		res.Tags["target_application_name"] = targetPod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["target_org_id"] = targetPod.Labels["DICE_ORG_ID"]
		res.Tags["target_project_id"] = targetPod.Labels["DICE_PROJECT_ID"]
		res.Tags["target_project_name"] = targetPod.Labels["DICE_PROJECT_NAME"]
		res.Tags["target_runtime_id"] = targetPod.Labels["DICE_RUNTIME_ID"]
		res.Tags["target_runtime_name"] = targetPod.Annotations["msp.erda.cloud/runtime_name"]
		res.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", targetPod.Labels["DICE_APPLICATION_ID"], targetPod.Annotations["msp.erda.cloud/runtime_name"], targetPod.Labels["DICE_SERVICE_NAME"])
		res.Tags["target_service_instance_id"] = string(targetPod.UID)
		res.Tags["target_service_name"] = targetPod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["target_terminus_key"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		res.Tags["target_workspace"] = targetPod.Annotations["msp.erda.cloud/workspace"]
	}
	sourcePod, err := p.kprobeHelper.GetPodByUID(m.DstIP)
	if err == nil {
		res.Tags["source_application_id"] = sourcePod.Labels["DICE_APPLICATION_ID"]
		res.Tags["source_application_name"] = sourcePod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["source_org_id"] = sourcePod.Labels["DICE_ORG_ID"]
		res.Tags["source_project_id"] = sourcePod.Labels["DICE_PROJECT_ID"]
		res.Tags["source_project_name"] = sourcePod.Labels["DICE_PROJECT_NAME"]
		res.Tags["source_runtime_id"] = sourcePod.Labels["DICE_RUNTIME_ID"]
		res.Tags["source_runtime_name"] = sourcePod.Annotations["msp.erda.cloud/runtime_name"]
		res.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Labels["DICE_APPLICATION_ID"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Labels["DICE_SERVICE_NAME"])
		res.Tags["source_workspace"] = sourcePod.Annotations["msp.erda.cloud/workspace"]
	}
	return res
}

func init() {
	servicehub.Register("rpc", &servicehub.Spec{
		Services:     []string{"rpc"},
		Description:  "ebpf for rpc",
		Dependencies: []string{"kprobe"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
