package network

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"hostberry/internal/config"
	"hostberry/internal/i18n"
	"hostberry/internal/utils"
	"hostberry/internal/validators"
)

func executeArgv(args ...string) (string, error) {
	return utils.ExecuteArgv(args...)
}

var ipv4Re = regexp.MustCompile(`(?m)(\b(?:\d{1,3}\.){3}\d{1,3}\b)`)

func getHostnameStatic() string {
	// Preferimos hostnamectl si está disponible.
	if out, err := exec.Command("hostnamectl", "--static").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" {
			return s
		}
	}
	if out, err := exec.Command("hostname").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func extractIPv4s(s string) []string {
	seen := map[string]struct{}{}
	var res []string
	for _, m := range ipv4Re.FindAllStringSubmatch(s, -1) {
		ip := strings.TrimSpace(m[1])
		if ip == "" {
			continue
		}
		if validators.ValidateIP(ip) != nil {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		res = append(res, ip)
	}
	return res
}

func getDefaultRouteGatewayAndIface() (gateway string, iface string) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "default") {
			continue
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				gateway = fields[i+1]
			}
			if fields[i] == "dev" {
				iface = fields[i+1]
			}
		}
		if gateway != "" && iface != "" {
			iface = strings.TrimSpace(iface)
			if validators.ValidateIfaceName(iface) == nil {
				return gateway, iface
			}
		}
	}
	return gateway, iface
}

func nmcliFirstActiveConnectionName() string {
	out, err := exec.Command("nmcli", "-t", "-f", "NAME", "connection", "show", "--active").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			return name
		}
	}
	return ""
}

// sudoCmd construye un comando privilegiado argv vía privileged-exec
// (sudoers solo autoriza el wrapper; `sudo` directo fallaría o colgaría).
func sudoCmd(args ...string) (*exec.Cmd, error) {
	return utils.NewArgvCommand(args...)
}

func writeFileWithSudoTee(path string, content string) error {
	cmd, err := sudoCmd("tee", path)
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_, err = cmd.CombinedOutput()
	return err
}

func writeFileBytesWithSudoTee(path string, content []byte) error {
	return writeFileWithSudoTee(path, string(content))
}

func NetworkRoutingHandler(c *fiber.Ctx) error {
	out, err := exec.Command("ip", "route").CombinedOutput()
	if err != nil {
		i18n.LogTf("logs.api_route_error", err, string(out))
		return c.Status(500).JSON(fiber.Map{"error": strings.TrimSpace(string(out))})
	}
	var routes []fiber.Map
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	i18n.LogTf("logs.api_processing_routes", len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}
		route := fiber.Map{"raw": line}
		route["destination"] = parts[0]

		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "via" && i+1 < len(parts) {
				route["gateway"] = parts[i+1]
			}
			if parts[i] == "dev" && i+1 < len(parts) {
				route["interface"] = parts[i+1]
			}
			if parts[i] == "metric" && i+1 < len(parts) {
				route["metric"] = parts[i+1]
			}
		}

		if _, hasGateway := route["gateway"]; !hasGateway {
			route["gateway"] = "*"
		}

		if _, hasInterface := route["interface"]; !hasInterface {
			route["interface"] = "-"
		}

		if _, hasMetric := route["metric"]; !hasMetric {
			route["metric"] = "0"
		}

		routes = append(routes, route)
	}

	i18n.LogTf("logs.api_returning_routes", len(routes))
	return c.JSON(routes)
}

func NetworkFirewallToggleHandler(c *fiber.Ctx) error {
	return c.Status(501).JSON(fiber.Map{"error": "Firewall toggle no implementado"})
}

func NetworkConfigHandler(c *fiber.Ctx) error {
	if c.Method() == "GET" {
		config := fiber.Map{
			"hostname": "",
			"gateway":  "",
			"dns1":     "",
			"dns2":     "",
		}

		config["hostname"] = getHostnameStatic()

		if gateway, iface := getDefaultRouteGatewayAndIface(); gateway != "" {
			_ = iface
			config["gateway"] = gateway
		}

		// DNS: prioritizamos nmcli activo -> resolvectl -> /etc/resolv.conf
		if connName := nmcliFirstActiveConnectionName(); connName != "" {
			if dnsOut, err := exec.Command("nmcli", "-t", "-f", "IP4.DNS", "connection", "show", connName).Output(); err == nil {
				ips := extractIPv4s(string(dnsOut))
				if len(ips) > 0 {
					config["dns1"] = ips[0]
				}
				if len(ips) > 1 {
					config["dns2"] = ips[1]
				}
			}
		}

		if config["dns1"] == "" {
			if resolveOut, err := exec.Command("resolvectl", "dns").Output(); err == nil {
				ips := extractIPv4s(string(resolveOut))
				if len(ips) > 0 {
					config["dns1"] = ips[0]
				}
				if len(ips) > 1 {
					config["dns2"] = ips[1]
				}
			}
		}

		if config["dns1"] == "" {
			if resolvOut, err := os.ReadFile("/etc/resolv.conf"); err == nil {
				lines := strings.Split(string(resolvOut), "\n")
				var ips []string
				seen := map[string]struct{}{}
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "nameserver ") {
						continue
					}
					fields := strings.Fields(line)
					if len(fields) < 2 {
						continue
					}
					ip := fields[1]
					if ip == "127.0.0.1" || ip == "127.0.0.53" {
						continue
					}
					if validators.ValidateIP(ip) != nil {
						continue
					}
					if _, ok := seen[ip]; ok {
						continue
					}
					seen[ip] = struct{}{}
					ips = append(ips, ip)
				}
				if len(ips) > 0 {
					config["dns1"] = ips[0]
				}
				if len(ips) > 1 {
					config["dns2"] = ips[1]
				}
			}
		}

		return c.JSON(config)
	}

	var req struct {
		Hostname string `json:"hostname"`
		DNS1     string `json:"dns1"`
		DNS2     string `json:"dns2"`
		Gateway  string `json:"gateway"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request body",
		})
	}

	errors := []string{}
	applied := []string{}

	if req.Hostname != "" {
		if len(req.Hostname) > 64 || len(req.Hostname) < 1 {
			errors = append(errors, "Hostname must be between 1 and 64 characters")
		} else {
			hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)
			if !hostnameRegex.MatchString(req.Hostname) {
				errors = append(errors, "Hostname contains invalid characters. Use only letters, numbers, hyphens and dots. Cannot start or end with hyphen or dot.")
			} else {
				hostnameApplied := false
				var lastError error
				var lastOutput string

				if !hostnameApplied {
					if out, err := executeArgv("hostnamectl", "set-hostname", req.Hostname); err == nil {
						time.Sleep(500 * time.Millisecond)
						currentHostname := getHostnameStatic()
						if currentHostname == req.Hostname {
							hostnameApplied = true
							i18n.LogTf("logs.api_hostname_set", req.Hostname)
							_ = out
						} else {
							i18n.LogTf("logs.api_hostname_verify_failed", req.Hostname, currentHostname)
							lastError = fmt.Errorf("verification failed: got %s", currentHostname)
							lastOutput = out
						}
					} else {
						i18n.LogTf("logs.api_hostnamectl_failed", err, out)
						lastError = err
						lastOutput = out
					}
				}

				if !hostnameApplied {
					hostnameFile := "/etc/hostname"
					tmpF, tmpErr := os.CreateTemp("", "hostberry-hostname-*")
					if tmpErr != nil {
						lastError = tmpErr
					} else {
						tmpHostname := tmpF.Name()
						tmpF.Close()
						defer os.Remove(tmpHostname)
						if wErr := os.WriteFile(tmpHostname, []byte(req.Hostname+"\n"), 0644); wErr == nil {
							defer os.Remove(tmpHostname)
							cpCmd, cpCmdErr := sudoCmd("cp", "-f", tmpHostname, hostnameFile)
							var cpOut []byte
							var cpErr error
							if cpCmdErr != nil {
								cpErr = cpCmdErr
							} else {
								cpOut, cpErr = cpCmd.CombinedOutput()
							}
							out := strings.TrimSpace(string(cpOut))
							if cpErr == nil {
								if content, err := os.ReadFile(hostnameFile); err == nil {
									writtenHostname := strings.TrimSpace(string(content))
									if writtenHostname == req.Hostname {
										if applyOut, applyErr := executeArgv("hostname", req.Hostname); applyErr == nil {
											verifyCmd := exec.Command("hostname")
											if verifyOut, err := verifyCmd.Output(); err == nil {
												currentHostname := strings.TrimSpace(string(verifyOut))
												if currentHostname == req.Hostname {
													hostnameApplied = true
													i18n.LogTf("logs.api_hostname_file_set", req.Hostname)
													_ = applyOut
												} else {
													i18n.LogTf("logs.api_hostname_file_verify_failed", req.Hostname, currentHostname)
													lastError = fmt.Errorf("verification failed: got %s", currentHostname)
													lastOutput = applyOut
												}
											}
										} else {
											i18n.LogTf("logs.api_hostname_apply_failed", applyErr, applyOut)
											lastError = applyErr
											lastOutput = applyOut
										}
									} else {
										i18n.LogTf("logs.api_hostname_write_mismatch", req.Hostname, writtenHostname)
										lastError = fmt.Errorf("written hostname mismatch")
										lastOutput = out
									}
								} else {
									i18n.LogTf("logs.api_hostname_read_failed", err)
									lastError = err
									lastOutput = out
								}
							} else {
								i18n.LogTf("logs.api_hostname_write_failed", cpErr, out)
								lastError = cpErr
								lastOutput = out
							}
						}
					}
				}

				if !hostnameApplied {
					if out, err := executeArgv("hostname", req.Hostname); err == nil {
						time.Sleep(200 * time.Millisecond)
						verifyCmd := exec.Command("hostname")
						if verifyOut, err := verifyCmd.Output(); err == nil {
							currentHostname := strings.TrimSpace(string(verifyOut))
							if currentHostname == req.Hostname {
								hostnameApplied = true
								i18n.LogTf("logs.api_hostname_temp_set", req.Hostname)
								_ = out
							} else {
								i18n.LogTf("logs.api_hostname_temp_verify_failed", req.Hostname, currentHostname)
								lastError = fmt.Errorf("verification failed: got %s", currentHostname)
								lastOutput = out
							}
						} else {
							i18n.LogTf("logs.api_hostname_verify_error2", err)
							lastError = err
							lastOutput = out
						}
					} else {
						i18n.LogTf("logs.api_hostname_cmd_failed", err, out)
						lastError = err
						lastOutput = out
					}
				}

				if hostnameApplied {
					hostsFile := "/etc/hosts"
					tmpF, tmpErr := os.CreateTemp("", "hostberry-hosts-*")
					if tmpErr != nil {
						i18n.LogTf("logs.api_hosts_temp_error", tmpErr)
					} else {
						tmpFile := tmpF.Name()
						tmpF.Close()
						defer os.Remove(tmpFile)

						i18n.LogTf("logs.api_hosts_creating", req.Hostname)

						newContent := "# See `man hosts` for details.\n"
						newContent += "#\n"
						newContent += "# By default, systemd-resolved or libnss-myhostname will resolve\n"
						newContent += "# localhost and the system hostname if they're not specified here.\n"

						if req.Hostname != "" {
							newContent += fmt.Sprintf("127.0.0.1\tlocalhost\t%s\n", req.Hostname)
						} else {
							newContent += "127.0.0.1\tlocalhost\n"
						}

						newContent += "::1\t\tlocalhost\n"

						// Preservar el resto de entradas (bloque AdBlock, hosts
						// personalizados, comentarios de marcadores): solo se
						// sustituyen las líneas loopback que gestionamos aquí.
						if existing, err := os.ReadFile(hostsFile); err == nil {
							for _, line := range strings.Split(string(existing), "\n") {
								trimmed := strings.TrimSpace(line)
								if trimmed == "" || strings.HasPrefix(trimmed, "#") {
									newContent += line + "\n"
									continue
								}
								fields := strings.Fields(trimmed)
								if len(fields) == 0 {
									continue
								}
								switch fields[0] {
								case "127.0.0.1", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1":
									continue
								}
								newContent += line + "\n"
							}
						}

						if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err != nil {
							i18n.LogTf("logs.api_hosts_temp_error", err)
						} else {
							log.Printf("Created new hosts file in /tmp: %s", tmpFile)

							if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
								log.Printf("Error: Temp file does not exist after creation")
							} else {
								log.Printf("Temp file verified: exists and readable")

								copySuccess := false

								log.Printf("Attempting to copy hosts file to %s", hostsFile)
								cpCmd, cpCmdErr := sudoCmd("cp", "-f", tmpFile, hostsFile)
								var cpOut []byte
								var cpErr error
								if cpCmdErr != nil {
									cpErr = cpCmdErr
								} else {
									cpOut, cpErr = cpCmd.CombinedOutput()
								}

								time.Sleep(200 * time.Millisecond)
								if content, err := os.ReadFile(hostsFile); err == nil {
									if strings.Contains(string(content), req.Hostname) {
										log.Printf("Successfully copied with cp - hostname found in /etc/hosts")
										copySuccess = true
									} else {
										if cpErr != nil {
											log.Printf("Error with cp: %v, output: %s", cpErr, string(cpOut))
										} else {
											log.Printf("cp command executed but hostname not found in /etc/hosts")
										}
										log.Printf("Verification failed after cp: hostname not found in /etc/hosts")

										if strings.Contains(string(cpOut), "Read-only file system") || strings.Contains(string(cpOut), "Read-only") {
											log.Printf("Warning: /etc/hosts appears to be on a read-only file system")
											log.Printf("Attempting to remount /etc as read-write...")
											remountCmd, remountCmdErr := sudoCmd("mount", "-o", "remount,rw", "/")
											var remountOut []byte
											var remountErr error
											if remountCmdErr != nil {
												remountErr = remountCmdErr
											} else {
												remountOut, remountErr = remountCmd.CombinedOutput()
											}
											if remountErr != nil {
												log.Printf("Could not remount / as read-write: %v, output: %s", remountErr, string(remountOut))
											} else {
												log.Printf("Successfully remounted / as read-write")
												cpCmd2, cpCmd2Err := sudoCmd("cp", "-f", tmpFile, hostsFile)
												if cpCmd2Err == nil {
													if _, cpErr2 := cpCmd2.CombinedOutput(); cpErr2 == nil {
														time.Sleep(200 * time.Millisecond)
														if content2, err2 := os.ReadFile(hostsFile); err2 == nil {
															if strings.Contains(string(content2), req.Hostname) {
																log.Printf("Successfully copied after remount - hostname found in /etc/hosts")
																copySuccess = true
															}
														}
													}
												}
											}
										}
									}
								} else {
									if cpErr != nil {
										log.Printf("Error with cp: %v, output: %s", cpErr, string(cpOut))
									} else {
										log.Printf("cp command executed but could not read /etc/hosts: %v", err)
									}
								}

								if !copySuccess {
									log.Printf("Trying alternative method: tee")
									if tmpContent, err := os.ReadFile(tmpFile); err == nil {
										if catErr := writeFileWithSudoTee(hostsFile, string(tmpContent)); catErr != nil {
											log.Printf("Error with cat/tee: %v", catErr)
										} else {
											log.Printf("cat/tee command executed")
											time.Sleep(100 * time.Millisecond)
											if content, err := os.ReadFile(hostsFile); err == nil {
												if strings.Contains(string(content), req.Hostname) {
													log.Printf("Successfully copied with cat/tee - hostname found in /etc/hosts")
													copySuccess = true
												} else {
													log.Printf("cat/tee executed but hostname not found in /etc/hosts")
													log.Printf("Verification failed after cat/tee: hostname not found in /etc/hosts")
												}
											}
										}
									} else {
										log.Printf("Error reading temp hosts file for tee: %v", err)
									}
								}

								if !copySuccess {
									// Reintento con tee (ya no usamos shell con redirecciones).
									log.Printf("Reintentando copia con tee sin shell")
									if tmpContent, err := os.ReadFile(tmpFile); err == nil {
										if err := writeFileWithSudoTee(hostsFile, string(tmpContent)); err == nil {
											time.Sleep(100 * time.Millisecond)
											if content, err := os.ReadFile(hostsFile); err == nil {
												if strings.Contains(string(content), req.Hostname) {
													log.Printf("Successfully copied with tee - hostname found in /etc/hosts")
													copySuccess = true
												} else {
													log.Printf("tee executed but hostname not found in /etc/hosts")
													log.Printf("Verification failed after tee: hostname not found in /etc/hosts")
												}
											}
										} else {
											log.Printf("Error with tee reintento: %v", err)
										}
									}
								}

								if copySuccess {
									if out, err := executeArgv("chmod", "644", hostsFile); err != nil {
										log.Printf("Warning: Could not set permissions: %v, output: %s", err, out)
									} else {
										log.Printf("Permissions set correctly")
									}

									if content, err := os.ReadFile(hostsFile); err == nil {
										if strings.Contains(string(content), req.Hostname) {
											log.Printf("Final verification: hostname %s successfully updated in /etc/hosts", req.Hostname)
										} else {
											log.Printf("Final verification failed: hostname not found")
											log.Printf("Final /etc/hosts content:\n%s", string(content))
										}
									}
								} else {
									log.Printf("Error: All copy methods failed. /etc/hosts was not updated.")
								}
							}

							os.Remove(tmpFile)
						}
					}

					applied = append(applied, fmt.Sprintf("Hostname set to %s and /etc/hosts updated", req.Hostname))
				} else {
					errorMsg := fmt.Sprintf("Failed to set hostname: tried hostnamectl, /etc/hostname, and hostname command")
					if lastError != nil {
						errorMsg += fmt.Sprintf(" (last error: %v", lastError)
						if lastOutput != "" {
							errorMsg += fmt.Sprintf(", output: %s", strings.TrimSpace(lastOutput))
						}
						errorMsg += ")"
					}
					errors = append(errors, errorMsg)
					if config.AppConfig.Server.Debug {
						log.Printf("All hostname setting methods failed for hostname: %s. Last error: %v, Last output: %s", req.Hostname, lastError, lastOutput)
					}
				}
			}
		}
	}

	dnsServers := []string{}
	if req.DNS1 != "" {
		if err := validators.ValidateIP(strings.TrimSpace(req.DNS1)); err != nil {
			errors = append(errors, "Invalid DNS1 format")
		} else {
			dnsServers = append(dnsServers, strings.TrimSpace(req.DNS1))
		}
	}

	if req.DNS2 != "" {
		if err := validators.ValidateIP(strings.TrimSpace(req.DNS2)); err != nil {
			errors = append(errors, "Invalid DNS2 format")
		} else {
			dnsServers = append(dnsServers, strings.TrimSpace(req.DNS2))
		}
	}

	if len(dnsServers) > 0 {
		dnsApplied := false
		dnsStr := strings.Join(dnsServers, " ")

		if !dnsApplied {
			connName := nmcliFirstActiveConnectionName()
			if connName != "" {
				out, err := runSudoNmcli("connection", "modify", connName, "ipv4.dns", dnsStr)
				if err == nil {
					if _, upErr := runSudoNmcli("connection", "up", connName); upErr != nil {
						log.Printf("nmcli connection up after DNS: %v", upErr)
					}
					applied = append(applied, fmt.Sprintf("DNS set to %s (via NetworkManager)", strings.Join(dnsServers, ", ")))
					dnsApplied = true
					log.Printf("DNS configured via nmcli: %s", dnsStr)
					_ = out
				} else {
					log.Printf("nmcli DNS configuration failed: %v, output: %s", err, out)
				}
			}
		}

		if !dnsApplied {
			resolvedConf := "/etc/systemd/resolved.conf"
			if _, err := os.Stat(resolvedConf); err == nil {
				content, err := os.ReadFile(resolvedConf)
				if err == nil {
					lines := strings.Split(string(content), "\n")
					updated := false
					newLines := []string{}

					for _, line := range lines {
						trimmed := strings.TrimSpace(line)
						if strings.HasPrefix(trimmed, "DNS=") {
							newLines = append(newLines, "DNS="+strings.Join(dnsServers, " "))
							updated = true
						} else if strings.HasPrefix(trimmed, "#DNS=") && !updated {
							newLines = append(newLines, "DNS="+strings.Join(dnsServers, " "))
							updated = true
						} else {
							newLines = append(newLines, line)
						}
					}

					if !updated {
						newLines = append(newLines, "DNS="+strings.Join(dnsServers, " "))
					}

					newContent := strings.Join(newLines, "\n")
					if err := writeFileWithSudoTee(resolvedConf, newContent); err == nil {
						_, _ = executeArgv("systemctl", "restart", "systemd-resolved")
						applied = append(applied, fmt.Sprintf("DNS set to %s (via systemd-resolved)", strings.Join(dnsServers, ", ")))
						dnsApplied = true
						log.Printf("DNS configured via systemd-resolved: %s", dnsStr)
					}
				}
			}
		}

		if !dnsApplied {
			resolvConf := "/etc/resolv.conf"
			_, _ = executeArgv("cp", resolvConf, resolvConf+".backup")

			content, err := os.ReadFile(resolvConf)
			if err == nil {
				lines := strings.Split(string(content), "\n")
				newLines := []string{}

				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if !strings.HasPrefix(trimmed, "nameserver") {
						newLines = append(newLines, line)
					}
				}

				for _, dns := range dnsServers {
					newLines = append(newLines, "nameserver "+dns)
				}

				newContent := strings.Join(newLines, "\n")
				if err := writeFileWithSudoTee(resolvConf, newContent); err == nil {
					applied = append(applied, fmt.Sprintf("DNS set to %s (via /etc/resolv.conf)", strings.Join(dnsServers, ", ")))
					dnsApplied = true
					log.Printf("DNS configured via /etc/resolv.conf: %s", dnsStr)
				} else {
					log.Printf("Failed to write /etc/resolv.conf: %v", err)
				}
			}
		}

		if !dnsApplied {
			errors = append(errors, fmt.Sprintf("Failed to set DNS: tried NetworkManager, systemd-resolved, and /etc/resolv.conf"))
		}
	}

	if req.Gateway != "" {
		if err := validators.ValidateIP(strings.TrimSpace(req.Gateway)); err != nil {
			errors = append(errors, "Invalid Gateway format")
		} else {
			req.Gateway = strings.TrimSpace(req.Gateway)
			gatewayApplied := false

			if !gatewayApplied {
				connName := nmcliFirstActiveConnectionName()
				if connName != "" {
					out, err := runSudoNmcli("connection", "modify", connName, "ipv4.gateway", req.Gateway)
					if err == nil {
						if _, upErr := runSudoNmcli("connection", "up", connName); upErr == nil {
							applied = append(applied, fmt.Sprintf("Gateway set to %s (via NetworkManager)", req.Gateway))
							gatewayApplied = true
							log.Printf("Gateway configured via nmcli: %s", req.Gateway)
						} else {
							log.Printf("Failed to apply gateway via nmcli: %v", upErr)
						}
						_ = out
					} else {
						log.Printf("nmcli gateway configuration failed: %v, output: %s", err, out)
					}
				}
			}

			if !gatewayApplied {
				_, iface := getDefaultRouteGatewayAndIface()
				if iface != "" && validators.ValidateIfaceName(iface) != nil {
					iface = ""
				}

				if iface != "" {
					_, _ = executeArgv("ip", "route", "del", "default")
					if out, err := executeArgv("ip", "route", "add", "default", "via", req.Gateway, "dev", iface); err == nil {
						applied = append(applied, fmt.Sprintf("Gateway set to %s (via ip route)", req.Gateway))
						gatewayApplied = true
						log.Printf("Gateway configured via ip route: %s on %s", req.Gateway, iface)
					} else {
						log.Printf("ip route gateway configuration failed: %v, output: %s", err, out)
					}
				} else {
					_, _ = executeArgv("ip", "route", "del", "default")
					if out, err := executeArgv("ip", "route", "add", "default", "via", req.Gateway); err == nil {
						applied = append(applied, fmt.Sprintf("Gateway set to %s (via ip route)", req.Gateway))
						gatewayApplied = true
						log.Printf("Gateway configured via ip route: %s", req.Gateway)
					} else {
						log.Printf("ip route gateway configuration failed: %v, output: %s", err, out)
					}
				}
			}

			if !gatewayApplied {
				iface := ""
				if out, err := executeArgv("ip", "route"); err == nil {
					for _, line := range strings.Split(out, "\n") {
						fields := strings.Fields(line)
						if len(fields) < 2 || fields[0] != "default" {
							continue
						}
						for i := 1; i+1 < len(fields); i++ {
							if fields[i] == "dev" {
								iface = fields[i+1]
								break
							}
						}
						if iface != "" {
							break
						}
					}
				}
				if iface != "" && validators.ValidateIfaceName(iface) != nil {
					iface = ""
				}

				if iface != "" {
					_, _ = executeArgv("ip", "route", "del", "default")
					if out, err := executeArgv("ip", "route", "add", "default", "via", req.Gateway, "dev", iface); err == nil {
						applied = append(applied, fmt.Sprintf("Gateway set to %s (via ip route)", req.Gateway))
						gatewayApplied = true
						log.Printf("Gateway configured via ip route: %s on %s", req.Gateway, iface)
					} else {
						log.Printf("ip route gateway configuration failed: %v, output: %s", err, out)
					}
				}
			}

			if !gatewayApplied {
				errors = append(errors, fmt.Sprintf("Failed to set gateway: tried NetworkManager, ip route, and route command"))
			}
		}
	}

	if len(errors) > 0 {
		errorMsg := strings.Join(errors, "; ")
		if len(applied) > 0 {
			errorMsg += " (Some settings were applied: " + strings.Join(applied, ", ") + ")"
		}
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"error":   errorMsg,
		})
	}

	message := "Configuration applied successfully"
	if len(applied) > 0 {
		message = strings.Join(applied, "; ")
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": message,
	})
}
