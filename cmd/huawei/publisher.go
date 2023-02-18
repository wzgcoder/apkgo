package huawei

import (
	"fmt"
	"time"

	"github.com/KevinGong2013/apkgo/cmd/shared"
)

func (c *Client) Do(req shared.PublishRequest) error {

	appId, err := c.fetchAppId(req.PackageName)
	if err != nil {
		return err
	}

	// 上传apk
	if err = c.upload(appId, req.ApkFile); err != nil {
		return err
	}

	// 需要3分钟后再尝试提交审核

	// 提交发布
	// 1分钟执行执行一次
	waitTimes := 3
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	fmt.Printf(" %d 分钟后尝试提交应用\n", waitTimes)
	for range t.C {
		if waitTimes <= 0 {
			r := c.submitApp(appId)
			if r.Code == 0 {
				t.Stop()
				return nil
			}

			fmt.Println(r.Message)
			fmt.Println("1 分钟后尝试重新提价")

			if waitTimes <= -60 {
				return fmt.Errorf("失败太多次了，请前往华为后台检查")
			}
		} else {
			fmt.Printf(" %d 分钟后尝试提交应用\n", waitTimes)
			waitTimes--
		}
	}

	return nil
}
