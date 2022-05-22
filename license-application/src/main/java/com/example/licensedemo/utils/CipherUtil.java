package com.example.licensedemo.utils;

import java.io.*;

/**
 * @Author: LiHuaZhi
 * @Description: 操作加密授权信息
 **/
public class CipherUtil {

    private static boolean isLinux = true;

    // 判断系统
    static {
        String osName = System.getProperty("os.name").toLowerCase();
        // 失败位linux系统
        isLinux = osName.contains("linux");
    }

    public static String getApplicationInfo() {
        String bios;
        String mainBoard;
        String cpuId;

        try {
            if (isLinux) {
                cpuId = getSerialNumber("dmidecode -t processor | grep 'ID'", "ID", ":");
                mainBoard = getSerialNumber("dmidecode | grep 'Serial Number'", "Serial Number", ":");
                bios = executeLinuxCmd("dmidecode -s bios-version");
            } else {
                cpuId = getWindowsInfoByFile("Processor", "ProcessorId");
                mainBoard = getWindowsInfoByFile("BaseBoard", "SerialNumber");
                bios = getBiosByWindows();
            }

            // 不判断是否为空
            cpuId = cpuId.replace(" ", "").trim();
            mainBoard = mainBoard.replace(" ", "").trim();
            bios = bios.replace(" ", "").trim();

            // 封装为key=value形式的字符串
            return "cpu=" + cpuId +
                    "&bios=" + bios +
                    "&mainBoard=" + mainBoard;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    /**
     * 获取windows BiosSN信息
     *
     * @return
     */
    private static String getBiosByWindows() {
        StringBuilder result = new StringBuilder();
        try {
            Runtime rt = Runtime.getRuntime();
            Process p = rt.exec("cmd.exe /c wmic bios get serialnumber");
            InputStream in = p.getInputStream();
            BufferedReader input = new BufferedReader(new InputStreamReader(
                    p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result.append(line);
            }
            input.close();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
        return result.toString().split("SerialNumber")[1].trim();
    }

    /**
     * @param record 关键字
     * @param symbol 区分字符
     * @return
     */
    private static String getWindowsInfoByFile(String record, String symbol) {
        StringBuilder result = new StringBuilder();
        File file = null;
        BufferedReader input = null;
        try {
            file = File.createTempFile("tmp", ".vbs");
            file.deleteOnExit();
            FileWriter fw = new FileWriter(file);
            String vbs = "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
                    + "Set colItems = objWMIService.ExecQuery _ \n" + "   (\"Select * from Win32_" + record + "\") \n"
                    + "For Each objItem in colItems \n" + "    Wscript.Echo objItem." + symbol + " \n"
                    + "    exit for  ' do the first cpu only! \n" + "Next \n";
            fw.write(vbs);
            fw.close();
            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result.append(line);
            }
        } catch (Exception e) {
            System.out.println("获取windows信息错误");
            e.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (file != null) {
                boolean delete = file.delete();
            }
        }
        return result.toString().trim();
    }


    /**
     * Linux脚本执行方法
     *
     * @param cmd
     * @param record
     * @param symbol
     * @return
     */
    public static String getSerialNumber(String cmd, String record, String symbol) {
        String execResult = executeLinuxCmd(cmd);
        System.out.println(execResult);
        String[] infos = execResult.split("\n");

        for (String info : infos) {
            info = info.trim();
            if (info.contains(record)) {
                String[] sn = info.split(symbol);
                return sn[1];
            }
        }
        return null;
    }

    /**
     * Linux脚本执行方法
     *
     * @param cmd
     * @return
     */
    public static String executeLinuxCmd(String cmd) {
        try {
            StringBuilder sb = new StringBuilder();
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
