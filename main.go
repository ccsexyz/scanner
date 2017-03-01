package main

import (
	"log"
	"net"
	"os"

	"github.com/urfave/cli"
)

func main() {
	myApp := cli.NewApp()
	myApp.Name = "scanner"
	myApp.Usage = "simple scanner"
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "target",
			Value: "0.0.0.0/0",
			Usage: "the targets you want to scan",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 80,
			Usage: "the port you want to scan",
		},
		cli.IntFlag{
			Name:  "limit",
			Value: 0,
			Usage: "the send limit per second",
		},
		cli.IntFlag{
			Name:  "times",
			Value: 1,
		},
	}
	myApp.Action = func(c *cli.Context) error {
		target := c.String("target")
		port := c.Int("port")
		limit := c.Int("limit")
		times := c.Int("times")
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			log.Fatal(err)
		}
		s, err := newScanner(port, ipnet, limit, times)
		if err != nil {
			log.Fatal(err)
		}
		s.run()
		return nil
	}
	myApp.Run(os.Args)
}
