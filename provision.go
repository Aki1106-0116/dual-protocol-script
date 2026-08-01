package main

import (
	"fmt"
	"sync"
	"time"
)

type ProvisionRequest struct {
	Region string
	Count  int
}

func (m *Manager) Provision(request ProvisionRequest) (*Job, error) {
	if request.Count < 1 || request.Count > m.maxSlots {
		return nil, fmt.Errorf("数量必须在 1-%d 之间", m.maxSlots)
	}
	nodes, err := m.pickNodes(request.Region, request.Count)
	if err != nil {
		return nil, err
	}
	labels := make([]string, len(nodes))
	for i, node := range nodes {
		label := node.CountryCode
		if label == "" {
			label = node.HostName
		}
		labels[i] = label + " 家宽出口"
	}
	where := request.Region
	if where == "" {
		where = "任意地区"
	}
	job := newJob(fmt.Sprintf("创建 %d 个 %s 出口", len(nodes), where), labels)
	m.jobs.Add(job)
	go m.runProvision(job, nodes)
	return job, nil
}

func (m *Manager) runProvision(job *Job, nodes []Node) {
	defer job.Finish()
	var wg sync.WaitGroup
	for i, node := range nodes {
		tunnel, err := m.Start(node)
		if err != nil {
			job.Set(i, "failed", err.Error())
			continue
		}
		job.Set(i, "running", "正在连接 "+node.HostName)
		wg.Add(1)
		go func(index int, tunnel *Tunnel) {
			defer wg.Done()
			deadline := time.Now().Add(5 * time.Minute)
			for time.Now().Before(deadline) {
				view := tunnel.view()
				switch view.Status {
				case "up":
					job.Set(index, "ok", view.ExitIP)
					return
				case "failed", "stopped":
					job.Set(index, "failed", view.Error)
					return
				}
				time.Sleep(time.Second)
			}
			job.Set(index, "failed", "连接超时")
		}(i, tunnel)
	}
	wg.Wait()
}
