using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace modulesinvoke
{
	public static class Win32
	{
		public const int MAX_PATH = 260;
		public const int MAX_MODULE_NAME32 = 255;

		public const uint TH32CS_SNAPHEAPLIST = 0x00000001;
		public const uint TH32CS_SNAPPROCESS = 0x00000002;
		public const uint TH32CS_SNAPTHREAD = 0x00000004;
		public const uint TH32CS_SNAPMODULE = 0x00000008;
		public const uint TH32CS_SNAPMODULE32 = 0x00000010;
		public const uint TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE);
		public const uint TH32CS_INHERIT = 0x80000000;

		public struct PROCESSENTRY32
		{
			public uint dwSize;
			public uint cntUsage;
			public uint th32ProcessID;
			public IntPtr th32DefaultHeapID;
			public uint th32ModuleID;
			public uint cntThreads;
			public uint th32ParentProcessID;
			public int pcPriClassBase;
			public uint dwFlags;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
			public string szExeFile;
		}

		public struct ModuleInfo32
		{
			public UInt32 dwSize;
			public UInt32 th32ModuleID;
			public UInt32 th32ProcessID;
			public UInt32 GlblcntUsage;
			public UInt32 ProccntUsage;
			public IntPtr modBaseAddr;
			public UInt32 modBaseSize;
			public IntPtr hModule;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_MODULE_NAME32 + 1)]
			public string szModule;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
			public string szExePath;
		}

		[DllImport("Kernel32.dll")]
		public static extern IntPtr CreateToolhelp32Snapshot(UInt32 dwFlags, UInt32 th32ProcessID);

		[DllImport("Kernel32.dll")]
		public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lpme);
		[DllImport("Kernel32.dll")]
		public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lpme);

		[DllImport("Kernel32.dll")]
		public static extern bool Module32First(IntPtr hSnapshot, ref ModuleInfo32 lpme);
		[DllImport("Kernel32.dll")]
		public static extern bool Module32Next(IntPtr hSnapshot, ref ModuleInfo32 lpme);

		[DllImport("Kernel32.dll")]
		public static extern bool CloseHandle(IntPtr handle);
	}

	public class SnapShot
	{
		//keys: module names
		//values: processes using that module
		public Dictionary<string, List<string>> Data { get; set; }

		public SnapShot()
		{
			Data = new Dictionary<string, List<string>>();

			IntPtr system = Win32.CreateToolhelp32Snapshot(Win32.TH32CS_SNAPALL | Win32.TH32CS_SNAPMODULE32, 0);

			Win32.PROCESSENTRY32 procInfo = new Win32.PROCESSENTRY32();
			procInfo.dwSize = (uint)Marshal.SizeOf(procInfo);
			Win32.ModuleInfo32 modInfo = new Win32.ModuleInfo32();
			modInfo.dwSize = (uint)Marshal.SizeOf(modInfo);

			if (Win32.Process32First(system, ref procInfo))
			{
				do
				{
					IntPtr process = Win32.CreateToolhelp32Snapshot(Win32.TH32CS_SNAPALL | Win32.TH32CS_SNAPMODULE32, procInfo.th32ProcessID);

					if (Win32.Module32First(process, ref modInfo))
					{
						do
						{
							if (!modInfo.szModule.Contains(".dll")) continue;

							if (!Data.ContainsKey(modInfo.szModule))
								Data[modInfo.szModule] = new List<string>();
							string value = procInfo.szExeFile;
							if (value.Contains('.') && value.IndexOf('.') > 0)
								value = value.Substring(0, procInfo.szExeFile.IndexOf("."));
							if (!Data[modInfo.szModule].Contains(value))
								Data[modInfo.szModule].Add(value);
						} while (Win32.Module32Next(process, ref modInfo));
					}
					Win32.CloseHandle(process);
				} while (Win32.Process32Next(system, ref procInfo));
			}
			Win32.CloseHandle(system);
		}
	}

	class Program
	{
		static void Main(string[] args)
		{
			/* Sample main */
			SnapShot snap = new SnapShot();
			if(snap.Data.ContainsKey("kernel32.dll"))
			{
				Console.WriteLine("Everything using kernel32.dll: ");
				foreach (string s in snap.Data["kernel32.dll"])
					Console.WriteLine("  " + s + ".exe");
			}
		}
	}
}
