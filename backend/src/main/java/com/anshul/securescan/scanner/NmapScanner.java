package com.anshul.securescan.scanner;

import com.anshul.securescan.dto.NmapScanResult;
import com.anshul.securescan.exception.NmapExecutionException;
import com.anshul.securescan.exception.NmapTimeoutException;
import com.anshul.securescan.model.AssessmentStatus;
import com.anshul.securescan.model.ScanProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Scanner component responsible for executing Nmap and returning parsed results.
 */
@Component
public class NmapScanner {

    private static final Logger logger = LoggerFactory.getLogger(NmapScanner.class);

    public NmapScanResult scanHost(String targetHost, String profileName) {
        if (targetHost == null || targetHost.isBlank()) {
            throw new NmapExecutionException("Target host cannot be empty");
        }

        ScanProfile profile = ScanProfile.fromString(profileName);
        List<String> command = buildCommand(profile, targetHost);
        Duration timeout = profile.getTimeoutDuration();

        // Perform DNS resolution for target IP
        String resolvedIp = resolveHostIp(targetHost);

        logger.info("Starting Nmap scan. Target: {}, Resolved IP: {}, Profile: {}, Timeout: {}s, Command: {}",
                targetHost, resolvedIp != null ? resolvedIp : "Unresolved", profile.name(), timeout.toSeconds(), String.join(" ", command));

        ProcessBuilder builder = new ProcessBuilder(command);
        // Do NOT redirect error stream into stdout to prevent XML contamination
        builder.redirectErrorStream(false);

        Instant start = Instant.now();
        ByteArrayOutputStream stdoutStream = new ByteArrayOutputStream();
        ByteArrayOutputStream stderrStream = new ByteArrayOutputStream();

        try {
            Process process = builder.start();

            // Reader thread for STDOUT (XML output)
            Thread stdoutReader = new Thread(() -> {
                try (var in = process.getInputStream()) {
                    byte[] buf = new byte[4096];
                    int r;
                    while ((r = in.read(buf)) != -1) {
                        stdoutStream.write(buf, 0, r);
                    }
                } catch (IOException ignored) {
                }
            }, "nmap-stdout-reader");

            // Reader thread for STDERR (warnings/errors)
            Thread stderrReader = new Thread(() -> {
                try (var in = process.getErrorStream()) {
                    byte[] buf = new byte[4096];
                    int r;
                    while ((r = in.read(buf)) != -1) {
                        stderrStream.write(buf, 0, r);
                    }
                } catch (IOException ignored) {
                }
            }, "nmap-stderr-reader");

            stdoutReader.setDaemon(true);
            stderrReader.setDaemon(true);
            stdoutReader.start();
            stderrReader.start();

            boolean finished = process.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                logger.warn("Nmap scan timed out after {}s for target: {}, profile: {}", timeout.toSeconds(), targetHost, profile.name());
                throw new NmapTimeoutException(timeout);
            }

            stdoutReader.join(2000);
            stderrReader.join(2000);

            int exitCode = process.exitValue();
            String stdoutXml = stdoutStream.toString(StandardCharsets.UTF_8);
            String stderrOutput = stderrStream.toString(StandardCharsets.UTF_8).trim();

            if (!stderrOutput.isBlank()) {
                logger.debug("Nmap stderr diagnostic output for {}: {}", targetHost, stderrOutput);
            }

            NmapParser parser = new NmapParser();
            NmapScanResult result = parser.parseXml(stdoutXml, profile, targetHost);

            double duration = Duration.between(start, Instant.now()).toMillis() / 1000.0;
            result.setScanDurationSeconds(duration);

            // Ensure host identity is preserved
            result.setHost(targetHost);

            // Populate IP address via DNS lookup if XML omitted it
            if ((result.getIpAddress() == null || "unknown".equalsIgnoreCase(result.getIpAddress())) && resolvedIp != null) {
                result.setIpAddress(resolvedIp);
            }

            // Determine Assessment Status cleanly
            if ("UNKNOWN".equalsIgnoreCase(result.getHostStatus()) && result.getOpenPorts().isEmpty()) {
                result.setAssessmentStatus(AssessmentStatus.INCONCLUSIVE);
            } else {
                result.setAssessmentStatus(AssessmentStatus.COMPLETED);
            }

            logger.info("Nmap scan completed. Target: {}, Profile: {}, ExitCode: {}, HostStatus: {}, AssessmentStatus: {}, IP: {}, Open Ports: {}, Duration: {}s",
                    targetHost, profile.name(), exitCode, result.getHostStatus(), result.getAssessmentStatus(),
                    result.getIpAddress() != null ? result.getIpAddress() : "Unresolved",
                    result.getOpenPorts().size(), duration);

            if (exitCode != 0 && result.getOpenPorts().isEmpty() && "UNKNOWN".equalsIgnoreCase(result.getHostStatus())) {
                throw new NmapExecutionException("Nmap process exited with status code " + exitCode + " without obtaining host status.");
            }

            return result;
        } catch (IOException ex) {
            logger.error("Failed to execute Nmap process for target: {}", targetHost, ex);
            throw new NmapExecutionException("Nmap is not installed or not executable on this system.", ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new NmapExecutionException("Nmap scan execution was interrupted.", ex);
        }
    }

    private String resolveHostIp(String targetHost) {
        try {
            InetAddress address = InetAddress.getByName(targetHost);
            return address.getHostAddress();
        } catch (UnknownHostException ex) {
            return null;
        }
    }

    private List<String> buildCommand(ScanProfile profile, String targetHost) {
        String nmapExec = resolveNmapExecutable();
        List<String> command = new ArrayList<>();
        command.add(nmapExec);
        command.addAll(profile.getNmapArguments());
        command.add(targetHost);
        return command;
    }

    private String resolveNmapExecutable() {
        String[] candidates = {
                "nmap",
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe"
        };

        for (String candidate : candidates) {
            if (isExecutableAvailable(candidate)) {
                return candidate;
            }
        }

        Optional<String> installedPath = findNmapInProgramFiles();
        if (installedPath.isPresent()) {
            return installedPath.get();
        }

        throw new NmapExecutionException("Nmap executable not found. Please install Nmap and ensure it is available on system PATH.");
    }

    private Optional<String> findNmapInProgramFiles() {
        String[] programFilesDirs = {
                System.getenv("ProgramFiles"),
                System.getenv("ProgramFiles(x86)"),
                System.getenv("ProgramW6432")
        };

        for (String baseDir : programFilesDirs) {
            if (baseDir == null || baseDir.isBlank()) {
                continue;
            }
            Path nmapPath = Paths.get(baseDir, "Nmap", "nmap.exe");
            if (Files.isRegularFile(nmapPath) && Files.isExecutable(nmapPath)) {
                return Optional.of(nmapPath.toAbsolutePath().toString());
            }
        }

        return Optional.empty();
    }

    private boolean isExecutableAvailable(String candidate) {
        try {
            Process process = new ProcessBuilder(candidate, "--version").start();
            boolean completed = process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return completed && process.exitValue() == 0;
        } catch (IOException ex) {
            return false;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
