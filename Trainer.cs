using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

internal static class Native
{
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint Alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint Alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr process, ulong address, out MEMORY_BASIC_INFORMATION buffer, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr process, ulong address, byte[] buffer, int size, out int read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr process, ulong address, byte[] buffer, int size, out int written);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint allocType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr process, ulong address, UIntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr process, IntPtr attr, UIntPtr stack, IntPtr start, IntPtr param, uint flags, out uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr process, IntPtr[] modules, int size, out int needed, uint filter);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetModuleFileNameEx(IntPtr process, IntPtr module, StringBuilder name, int size);
}

internal sealed class PowerHit
{
    public ulong Entry0;
    public ulong[] ValueAddress = new ulong[7];
    public double[] Value = new double[7];
}

internal sealed class StatsHit
{
    public ulong Base;
    public ulong NpCap;
    public ulong RpCap;
    public ulong Boost;
    public double NpCapValue;
    public double RpCapValue;
    public double BoostValue;
}

internal static class Scanner
{
    private const int EntrySize = 24;
    private const int EntryCount = 7;

    private static bool IsReal(double v)
    {
        return !double.IsNaN(v) && !double.IsInfinity(v);
    }

    public static void FindAll(IntPtr process, List<PowerHit> powers, List<StatsHit> stats, MonoLayout layout, List<ulong> players)
    {
        foreach (Region region in EnumerateRegions(process))
        {
            ScanPower(region, powers);
            ScanStats(region, stats);
            ScanPlayers(region, layout, players);
        }
    }

    private static void ScanPlayers(Region region, MonoLayout layout, List<ulong> hits)
    {
        if (layout == null || !layout.Ok || hits == null)
            return;
        byte[] sig = BitConverter.GetBytes(layout.Vtable);
        int limit = region.Length - layout.InstanceSize;
        for (int i = 0; i <= limit; i += 8)
        {
            if (region[i] != sig[0] || region[i + 1] != sig[1] || region[i + 2] != sig[2] || region[i + 3] != sig[3]
                || region[i + 4] != sig[4] || region[i + 5] != sig[5] || region[i + 6] != sig[6] || region[i + 7] != sig[7])
                continue;
            if (!SanePlayer(region, i, layout))
                continue;
            hits.Add(region.Base + (ulong)i);
            i += layout.InstanceSize - 8;
        }
    }

    private static bool SanePlayer(Region region, int i, MonoLayout layout)
    {
        int maxJ = BitConverter.ToInt32(region.Data, i + layout.MaxAirJumps);
        int maxD = BitConverter.ToInt32(region.Data, i + layout.MaxAirDashes);
        int ground = BitConverter.ToInt32(region.Data, i + layout.GroundType);
        int cut = BitConverter.ToInt32(region.Data, i + layout.CutsceneMode);
        int wallLeft = BitConverter.ToInt32(region.Data, i + layout.WallJumpsLeft);
        if (maxJ < 0 || maxJ > 99 || maxD < 0 || maxD > 99)
            return false;
        if (ground < 0 || ground > 1 || cut < 0 || cut > 4 || wallLeft < -2 || wallLeft > 99)
            return false;
        if (region[i + layout.OnGround] > 1 || region[i + layout.OnWall] > 1 || region[i + layout.IsDead] > 1)
            return false;
        if (region[i + layout.DoubleJumpUnlocked] > 1 || region[i + layout.DashUnlocked] > 1)
            return false;
        return true;
    }

    private static void ScanPower(Region region, List<PowerHit> hits)
    {
        int limit = region.Length - EntryCount * EntrySize;
        for (int i = 0; i <= limit; i += 8)
        {
            if (region[i] != 0 || region[i + 1] != 0 || region[i + 2] != 0 || region[i + 3] != 0)
                continue;
            if (region[i + 4] != 0xFF || region[i + 5] != 0xFF || region[i + 6] != 0xFF || region[i + 7] != 0xFF)
                continue;
            if (!IsCurrencyBlock(region, i))
                continue;
            hits.Add(ReadHit(region, i));
            i += EntryCount * EntrySize - 8;
        }
    }

    private static IEnumerable<Region> EnumerateRegions(IntPtr process)
    {
        ulong addr = 0;
        int mbiSize = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
        while (addr < 0x00007FFFFFFFFFFFUL)
        {
            Native.MEMORY_BASIC_INFORMATION mbi;
            int q = Native.VirtualQueryEx(process, addr, out mbi, mbiSize);
            if (q == 0)
                break;
            ulong next = mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr)
                break;
            uint prot = mbi.Protect & 0xFF;
            bool readable = prot == 0x04 || prot == 0x08 || prot == 0x40 || prot == 0x80;
            // Private heap only. Image mappings are DLLs and only add false hits.
            if (mbi.Type == 0x20000
                && mbi.State == Native.MEM_COMMIT
                && (mbi.Protect & Native.PAGE_GUARD) == 0
                && readable
                && mbi.RegionSize > 0
                && mbi.RegionSize < 256UL * 1024 * 1024)
            {
                int size = (int)mbi.RegionSize;
                byte[] buf = new byte[size];
                int read;
                if (Native.ReadProcessMemory(process, mbi.BaseAddress, buf, size, out read) && read > EntryCount * EntrySize)
                {
                    if (read != size)
                    {
                        byte[] trimmed = new byte[read];
                        Buffer.BlockCopy(buf, 0, trimmed, 0, read);
                        buf = trimmed;
                    }
                    yield return new Region(mbi.BaseAddress, buf);
                }
            }
            addr = next;
        }
    }

    private struct Region
    {
        public ulong Base;
        public byte[] Data;
        public Region(ulong b, byte[] d) { Base = b; Data = d; }
        public int Length { get { return Data.Length; } }
        public byte this[int i] { get { return Data[i]; } }
    }

    private static bool IsCurrencyBlock(Region region, int offset)
    {
        if (offset < 8)
            return false;
        long slots = BitConverter.ToInt64(region.Data, offset - 8);
        if (slots < 7 || slots > 64)
            return false;
        if (slots > 7)
        {
            int extra = offset + 7 * EntrySize;
            if (extra + 4 > region.Length)
                return false;
            if (BitConverter.ToInt32(region.Data, extra) >= 0)
                return false;
        }
        for (int n = 0; n < EntryCount; n++)
        {
            int o = offset + n * EntrySize;
            int hash = BitConverter.ToInt32(region.Data, o);
            int next = BitConverter.ToInt32(region.Data, o + 4);
            int key = BitConverter.ToInt32(region.Data, o + 8);
            int pad = BitConverter.ToInt32(region.Data, o + 12);
            if (hash != n || next != -1 || key != n || pad != 0)
                return false;
            double v = BitConverter.ToDouble(region.Data, o + 16);
            // Incremental saves go past 1e300. Reject only non-finite values.
            if (double.IsNaN(v) || double.IsInfinity(v) || v < -1e-6)
                return false;
        }
        return true;
    }

    private static PowerHit ReadHit(Region region, int offset)
    {
        var hit = new PowerHit();
        hit.Entry0 = region.Base + (ulong)offset;
        for (int n = 0; n < EntryCount; n++)
        {
            int o = offset + n * EntrySize;
            hit.ValueAddress[n] = region.Base + (ulong)(o + 16);
            hit.Value[n] = BitConverter.ToDouble(region.Data, o + 16);
        }
        return hit;
    }

    private static void ScanStats(Region region, List<StatsHit> hits)
    {
        // Mono groups reference fields first, so the List that used to sit between
        // these doubles is not between them. Cap layout from NPrewardCap:
        // -0x18 per tick, -8 boost, +0x28 vmanMult, +0x30 rpCap.
        // cap == perTick * 6000 * vmanMult.
        const int needBefore = 0x18;
        const int needAfter = 0x38;
        int limit = region.Length - needAfter;
        for (int i = needBefore; i <= limit; i += 8)
        {
            uint hi = BitConverter.ToUInt32(region.Data, i + 4);
            int exp = (int)((hi >> 20) & 0x7FF);
            if (exp < 1043 || exp >= 2047)
                continue;
            double cap = BitConverter.ToDouble(region.Data, i);
            if (!IsReal(cap) || cap < 1e6)
                continue;
            double perTick = BitConverter.ToDouble(region.Data, i - 0x18);
            if (!IsReal(perTick) || perTick <= 0)
                continue;
            double mult = BitConverter.ToDouble(region.Data, i + 0x28);
            if (!IsReal(mult) || mult < 0.5 || mult > 1e12)
                continue;
            double expected = perTick * 6000.0 * mult;
            if (Math.Abs(expected - cap) / cap > 0.002)
                continue;
            double boost = BitConverter.ToDouble(region.Data, i - 8);
            double rp = BitConverter.ToDouble(region.Data, i + 0x30);
            if (!IsReal(boost) || !IsReal(rp) || boost < 0.01 || boost > 1e9 || rp < 1 || rp > 1e12)
                continue;
            var hit = new StatsHit();
            hit.Base = region.Base + (ulong)i - 0x50;
            hit.NpCap = region.Base + (ulong)i;
            hit.Boost = region.Base + (ulong)(i - 8);
            hit.RpCap = region.Base + (ulong)(i + 0x30);
            hit.NpCapValue = cap;
            hit.BoostValue = boost;
            hit.RpCapValue = rp;
            hits.Add(hit);
        }
    }
}

internal static class Format
{
    public static string Game(double value, string suffix)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
            return "?";
        if (value >= 1e18)
            return value.ToString("0.00e0", CultureInfo.InvariantCulture) + suffix;
        if (value / 1e15 > 1.0)
            return (Math.Round(value / 1e15 * 100.0) / 100.0).ToString("0.00", CultureInfo.InvariantCulture) + "P" + suffix;
        if (value / 1e12 >= 1.0)
            return (Math.Round(value / 1e12 * 100.0) / 100.0).ToString("0.00", CultureInfo.InvariantCulture) + "T" + suffix;
        if (value / 1e9 >= 1.0)
            return (Math.Round(value / 1e9 * 100.0) / 100.0).ToString("0.00", CultureInfo.InvariantCulture) + "G" + suffix;
        if (value / 1e6 >= 1.0)
            return (Math.Round(value / 1e6 * 100.0) / 100.0).ToString("0.00", CultureInfo.InvariantCulture) + "M" + suffix;
        if (value / 1e3 >= 1.0)
            return (Math.Round(value / 1e3 * 100.0) / 100.0).ToString("0.00", CultureInfo.InvariantCulture) + "K" + suffix;
        if (value > 0)
            return Math.Round(value).ToString(CultureInfo.InvariantCulture) + suffix;
        return "0" + suffix;
    }

    public static bool TryParse(string text, out double value)
    {
        value = 0;
        if (text == null)
            return false;
        text = text.Trim().Replace(" ", "");
        if (text.Length == 0)
            return false;
        text = text.Replace(",", "");
        double scale = 1;
        char last = text[text.Length - 1];
        if (last == 'P' || last == 'p') { scale = 1e15; text = text.Substring(0, text.Length - 1); }
        else if (last == 'T' || last == 't') { scale = 1e12; text = text.Substring(0, text.Length - 1); }
        else if (last == 'G' || last == 'g') { scale = 1e9; text = text.Substring(0, text.Length - 1); }
        else if (last == 'M' || last == 'm') { scale = 1e6; text = text.Substring(0, text.Length - 1); }
        else if (last == 'K' || last == 'k') { scale = 1e3; text = text.Substring(0, text.Length - 1); }
        double n;
        if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out n))
            return false;
        value = n * scale;
        return !double.IsNaN(value) && !double.IsInfinity(value);
    }
}

internal sealed class MonoLayout
{
    public ulong Vtable;
    public int InstanceSize;
    public ulong OnDeath;
    public ulong Moss;
    public ulong Solid;
    public int GroundType;
    public int OnGround;
    public int OnWall;
    public int AirJumpsLeft;
    public int MaxAirJumps;
    public int AirDashesLeft;
    public int MaxAirDashes;
    public int WallJumpsLeft;
    public int MaxWallJumps;
    public int Sweating;
    public int Cling;
    public int DashCooldown;
    public int DashUnlocked;
    public int DoubleJumpUnlocked;
    public int IsDead;
    public int CutsceneMode;
    public ulong SpeedAddress;
    public string Error;

    public bool Ok
    {
        get { return Vtable != 0 && InstanceSize > 64 && MaxAirJumps > 0 && OnGround > 0 && GroundType > 0; }
    }
}

internal static class MonoProbe
{
    public static MonoLayout Resolve(IntPtr process)
    {
        var layout = new MonoLayout();
        ulong monoBase;
        string monoPath;
        if (!FindMono(process, out monoBase, out monoPath))
        {
            layout.Error = "mono dll not found";
            return layout;
        }
        Dictionary<string, ulong> exp = Exports(monoPath, monoBase);
        string[] need = new string[] {
            "mono_get_root_domain", "mono_thread_attach", "mono_thread_detach",
            "mono_image_loaded", "mono_class_from_name", "mono_class_vtable",
            "mono_class_get_fields", "mono_field_get_name", "mono_field_get_offset",
            "mono_class_instance_size", "mono_class_get_method_from_name", "mono_compile_method"
        };
        for (int i = 0; i < need.Length; i++)
        {
            if (!exp.ContainsKey(need[i]))
            {
                layout.Error = "missing " + need[i];
                return layout;
            }
        }

        IntPtr block = Native.VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)0x10000, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
        if (block == IntPtr.Zero)
        {
            layout.Error = "alloc failed " + Marshal.GetLastWin32Error();
            return layout;
        }
        ulong baseAddr = (ulong)block.ToInt64();
        try
        {
            ulong str = baseAddr + 0x800;
            ulong output = baseAddr + 0x1000;
            ulong iter = baseAddr + 0xE000;
            ulong field = baseAddr + 0xE010;
            ulong offs = baseAddr + 0xE018;
            ulong stat = baseAddr + 0xE020;
            byte[] strings = new byte[0x400];
            ulong img = Put(strings, str, 0, "Assembly-CSharp");
            ulong ns = Put(strings, str, 0x40, "");
            ulong cls = Put(strings, str, 0x80, "Movement");
            ulong nDeath = Put(strings, str, 0xC0, "onDeath");
            ulong nMoss = Put(strings, str, 0x100, "touchedMossyGround");
            ulong nSolid = Put(strings, str, 0x140, "touchedSolidGround");
            byte[] code = Build(exp, output, iter, field, offs, stat, img, ns, cls, nDeath, nMoss, nSolid);
            Write(process, str, strings);
            Write(process, output, new byte[0x3000]);
            Write(process, iter, new byte[0x40]);
            Write(process, baseAddr, code);
            uint tid;
            IntPtr thread = Native.CreateRemoteThread(process, IntPtr.Zero, UIntPtr.Zero, block, IntPtr.Zero, 0, out tid);
            if (thread == IntPtr.Zero)
            {
                layout.Error = "remote thread " + Marshal.GetLastWin32Error();
                return layout;
            }
            Native.WaitForSingleObject(thread, 8000);
            Native.CloseHandle(thread);
            byte[] raw = new byte[0x2100];
            int got;
            if (!Native.ReadProcessMemory(process, output, raw, raw.Length, out got) || got < 48)
            {
                layout.Error = "probe read failed";
                return layout;
            }
            layout.Vtable = BitConverter.ToUInt64(raw, 32);
            layout.InstanceSize = BitConverter.ToInt32(raw, 40);
            int count = BitConverter.ToInt32(raw, 44);
            var fields = new Dictionary<string, int>();
            int n = count;
            if (n > 240)
                n = 240;
            for (int i = 0; i < n; i++)
            {
                int off = BitConverter.ToInt32(raw, 48 + i * 16);
                ulong namePtr = BitConverter.ToUInt64(raw, 48 + i * 16 + 8);
                string name = ReadCString(process, namePtr);
                if (name.Length > 0 && !fields.ContainsKey(name))
                    fields[name] = off;
            }
            layout.GroundType = Take(fields, "currentGroundType");
            layout.OnGround = Take(fields, "onGround");
            layout.OnWall = Take(fields, "OnWall");
            layout.AirJumpsLeft = Take(fields, "airJumpsLeft");
            layout.MaxAirJumps = Take(fields, "maxAirJumps");
            layout.AirDashesLeft = Take(fields, "airDashesLeft");
            layout.MaxAirDashes = Take(fields, "maxAirDashes");
            layout.WallJumpsLeft = Take(fields, "wallJumpsLeft");
            layout.MaxWallJumps = Take(fields, "maxWallJumps");
            layout.Sweating = Take(fields, "Sweating");
            layout.Cling = Take(fields, "isFinalWallClingActive");
            layout.DashCooldown = Take(fields, "dashCooldown");
            layout.DashUnlocked = Take(fields, "dashUnlocked");
            layout.DoubleJumpUnlocked = Take(fields, "doubleJumpUnlocked");
            layout.IsDead = Take(fields, "isDead");
            layout.CutsceneMode = Take(fields, "cutsceneMode");
            layout.OnDeath = BitConverter.ToUInt64(raw, 0x2008);
            layout.Moss = BitConverter.ToUInt64(raw, 0x2028);
            layout.Solid = BitConverter.ToUInt64(raw, 0x2048);
            if (!layout.Ok)
                layout.Error = "Movement fields missing";
        }
        finally
        {
            Native.VirtualFreeEx(process, block, UIntPtr.Zero, Native.MEM_RELEASE);
        }
        return layout;
    }

    public static void FillSpeed(IntPtr process, MonoLayout layout)
    {
        if (layout == null)
            return;
        IntPtr block = Native.VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)0x4000, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
        if (block == IntPtr.Zero)
            return;
        ulong baseAddr = (ulong)block.ToInt64();
        try
        {
            ulong monoBase;
            string monoPath;
            if (!FindMono(process, out monoBase, out monoPath))
                return;
            Dictionary<string, ulong> exp = Exports(monoPath, monoBase);
            if (!exp.ContainsKey("mono_class_get_field_from_name") || !exp.ContainsKey("mono_vtable_get_static_field_data"))
                return;
            ulong str = baseAddr + 0x200;
            ulong output = baseAddr + 0x800;
            byte[] strings = new byte[0x200];
            ulong img = Put(strings, str, 0, "Assembly-CSharp");
            ulong ns = Put(strings, str, 0x40, "");
            ulong cls = Put(strings, str, 0x80, "globalStats");
            ulong fld = Put(strings, str, 0xC0, "baseGameSpeed");
            byte[] code = BuildSpeed(exp, output, img, ns, cls, fld);
            Write(process, str, strings);
            Write(process, output, new byte[64]);
            Write(process, baseAddr, code);
            uint tid;
            IntPtr thread = Native.CreateRemoteThread(process, IntPtr.Zero, UIntPtr.Zero, block, IntPtr.Zero, 0, out tid);
            if (thread == IntPtr.Zero)
                return;
            Native.WaitForSingleObject(thread, 8000);
            Native.CloseHandle(thread);
            byte[] raw = new byte[64];
            int got;
            if (!Native.ReadProcessMemory(process, output, raw, raw.Length, out got) || got < 56)
                return;
            int offset = BitConverter.ToInt32(raw, 40);
            ulong data = BitConverter.ToUInt64(raw, 48);
            if (data == 0)
                return;
            layout.SpeedAddress = data + (ulong)offset;
        }
        finally
        {
            Native.VirtualFreeEx(process, block, UIntPtr.Zero, Native.MEM_RELEASE);
        }
    }

    private static byte[] BuildSpeed(Dictionary<string, ulong> exp, ulong output, ulong img, ulong ns, ulong cls, ulong fld)
    {
        Asm a = new Asm();
        a.E(0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20);
        Call(a, exp["mono_get_root_domain"]);
        StoreRax(a, output);
        a.E(0x48, 0x89, 0xC1);
        Call(a, exp["mono_thread_attach"]);
        StoreRax(a, output + 8);
        MovRcx(a, img);
        Call(a, exp["mono_image_loaded"]);
        StoreRax(a, output + 16);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "bad");
        a.E(0x48, 0x89, 0xC1);
        MovRdx(a, ns);
        MovR8(a, cls);
        Call(a, exp["mono_class_from_name"]);
        StoreRax(a, output + 24);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "bad");
        a.E(0x48, 0x89, 0xC1);
        MovRdx(a, fld);
        Call(a, exp["mono_class_get_field_from_name"]);
        StoreRax(a, output + 32);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "bad");
        a.E(0x48, 0x89, 0xC1);
        Call(a, exp["mono_field_get_offset"]);
        MovR11(a, output + 40);
        a.E(0x41, 0x89, 0x03);
        MovR11(a, output);
        a.E(0x49, 0x8B, 0x0B);
        MovR11(a, output + 24);
        a.E(0x49, 0x8B, 0x13);
        Call(a, exp["mono_class_vtable"]);
        a.E(0x48, 0x89, 0xC1);
        Call(a, exp["mono_vtable_get_static_field_data"]);
        StoreRax(a, output + 48);
        a.Lab("bad");
        MovR11(a, output + 8);
        a.E(0x49, 0x8B, 0x0B);
        a.E(0x48, 0x85, 0xC9);
        a.J(new byte[] { 0x0F, 0x84 }, "ret");
        Call(a, exp["mono_thread_detach"]);
        a.Lab("ret");
        a.E(0x31, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3);
        return a.Done();
    }

    private static int Take(Dictionary<string, int> fields, string name)
    {
        int value;
        if (fields.TryGetValue(name, out value))
            return value;
        return 0;
    }

    private static ulong Put(byte[] buf, ulong strBase, int offset, string text)
    {
        byte[] raw = Encoding.ASCII.GetBytes(text);
        Buffer.BlockCopy(raw, 0, buf, offset, raw.Length);
        buf[offset + raw.Length] = 0;
        return strBase + (ulong)offset;
    }

    private static void Write(IntPtr process, ulong address, byte[] data)
    {
        int written;
        if (!Native.WriteProcessMemory(process, address, data, data.Length, out written) || written != data.Length)
            throw new InvalidOperationException("write failed " + Marshal.GetLastWin32Error());
    }

    private static string ReadCString(IntPtr process, ulong address)
    {
        if (address == 0)
            return "";
        byte[] buf = new byte[80];
        int got;
        if (!Native.ReadProcessMemory(process, address, buf, buf.Length, out got) || got <= 0)
            return "";
        int n = 0;
        while (n < got && buf[n] != 0)
            n++;
        return Encoding.ASCII.GetString(buf, 0, n);
    }

    private static bool FindMono(IntPtr process, out ulong baseAddr, out string path)
    {
        baseAddr = 0;
        path = null;
        IntPtr[] mods = new IntPtr[1024];
        int needed;
        if (!Native.EnumProcessModulesEx(process, mods, mods.Length * IntPtr.Size, out needed, 3))
            return false;
        int count = needed / IntPtr.Size;
        if (count > mods.Length)
            count = mods.Length;
        for (int i = 0; i < count; i++)
        {
            StringBuilder name = new StringBuilder(520);
            if (Native.GetModuleFileNameEx(process, mods[i], name, name.Capacity) == 0)
                continue;
            string file = name.ToString();
            if (file.EndsWith("mono-2.0-bdwgc.dll", StringComparison.OrdinalIgnoreCase))
            {
                baseAddr = (ulong)mods[i].ToInt64();
                path = file;
                return true;
            }
        }
        return false;
    }

    private static Dictionary<string, ulong> Exports(string path, ulong moduleBase)
    {
        byte[] data = File.ReadAllBytes(path);
        int elf = BitConverter.ToInt32(data, 0x3C);
        int nsec = BitConverter.ToUInt16(data, elf + 6);
        int optSize = BitConverter.ToUInt16(data, elf + 20);
        int opt = elf + 24;
        int expRva = BitConverter.ToInt32(data, opt + 112);
        int secOff = opt + optSize;
        int[] va = new int[nsec];
        int[] sz = new int[nsec];
        int[] raw = new int[nsec];
        for (int i = 0; i < nsec; i++)
        {
            int o = secOff + 40 * i;
            int vsz = BitConverter.ToInt32(data, o + 8);
            va[i] = BitConverter.ToInt32(data, o + 12);
            int rsz = BitConverter.ToInt32(data, o + 16);
            raw[i] = BitConverter.ToInt32(data, o + 20);
            sz[i] = vsz > rsz ? vsz : rsz;
        }
        int eo = Rva(va, sz, raw, expRva);
        int nnames = BitConverter.ToInt32(data, eo + 24);
        int funcsRva = BitConverter.ToInt32(data, eo + 28);
        int namesRva = BitConverter.ToInt32(data, eo + 32);
        int ordsRva = BitConverter.ToInt32(data, eo + 36);
        int namesOff = Rva(va, sz, raw, namesRva);
        int ordsOff = Rva(va, sz, raw, ordsRva);
        int funcsOff = Rva(va, sz, raw, funcsRva);
        var map = new Dictionary<string, ulong>();
        for (int i = 0; i < nnames; i++)
        {
            int nrva = BitConverter.ToInt32(data, namesOff + 4 * i);
            int no = Rva(va, sz, raw, nrva);
            int end = no;
            while (end < data.Length && data[end] != 0)
                end++;
            string name = Encoding.ASCII.GetString(data, no, end - no);
            if (name.StartsWith("mono_", StringComparison.Ordinal))
            {
                int ord = BitConverter.ToUInt16(data, ordsOff + 2 * i);
                int frva = BitConverter.ToInt32(data, funcsOff + 4 * ord);
                map[name] = moduleBase + (ulong)frva;
            }
        }
        return map;
    }

    private static int Rva(int[] va, int[] sz, int[] raw, int rva)
    {
        for (int i = 0; i < va.Length; i++)
        {
            if (rva >= va[i] && rva < va[i] + sz[i])
                return raw[i] + (rva - va[i]);
        }
        throw new InvalidOperationException("bad rva");
    }

    private static byte[] Build(Dictionary<string, ulong> exp, ulong output, ulong iter, ulong field, ulong offs, ulong stat, ulong img, ulong ns, ulong cls, ulong nDeath, ulong nMoss, ulong nSolid)
    {
        Asm a = new Asm();
        a.E(0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20);
        Call(a, exp["mono_get_root_domain"]);
        StoreRax(a, output);
        a.E(0x48, 0x89, 0xC1);
        Call(a, exp["mono_thread_attach"]);
        StoreRax(a, output + 8);
        MovRcx(a, img);
        Call(a, exp["mono_image_loaded"]);
        StoreRax(a, output + 16);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "noimg");
        a.E(0x48, 0x89, 0xC1);
        MovRdx(a, ns);
        MovR8(a, cls);
        Call(a, exp["mono_class_from_name"]);
        StoreRax(a, output + 24);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "nocls");
        MovR11(a, output);
        a.E(0x49, 0x8B, 0x0B);
        a.E(0x49, 0x8B, 0x53, 0x18);
        Call(a, exp["mono_class_vtable"]);
        StoreRax(a, output + 32);
        MovR11(a, output + 24);
        a.E(0x49, 0x8B, 0x0B);
        Call(a, exp["mono_class_instance_size"]);
        MovR11(a, output + 40);
        a.E(0x41, 0x89, 0x03);
        MovR11(a, iter);
        a.E(0x49, 0xC7, 0x03, 0x00, 0x00, 0x00, 0x00);
        a.Lab("loop");
        MovR11(a, output + 24);
        a.E(0x49, 0x8B, 0x0B);
        MovR11(a, iter);
        a.E(0x49, 0x8D, 0x13);
        Call(a, exp["mono_class_get_fields"]);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, "methods");
        StoreRax(a, field);
        MovR11(a, output + 44);
        a.E(0x41, 0x8B, 0x0B);
        a.E(0x81, 0xF9, 0xF0, 0x00, 0x00, 0x00);
        a.J(new byte[] { 0x0F, 0x8D }, "methods");
        MovR11(a, field);
        a.E(0x49, 0x8B, 0x0B);
        Call(a, exp["mono_field_get_offset"]);
        MovR11(a, offs);
        a.E(0x41, 0x89, 0x03);
        MovR11(a, field);
        a.E(0x49, 0x8B, 0x0B);
        Call(a, exp["mono_field_get_name"]);
        a.E(0x49, 0x89, 0xC2);
        MovR11(a, output + 44);
        a.E(0x41, 0x8B, 0x0B);
        a.E(0x6B, 0xC9, 0x10);
        MovR11(a, offs);
        a.E(0x41, 0x8B, 0x03);
        MovR11(a, output + 48);
        a.E(0x49, 0x01, 0xCB);
        a.E(0x41, 0x89, 0x03);
        a.E(0x4D, 0x89, 0x53, 0x08);
        MovR11(a, output + 44);
        a.E(0x41, 0xFF, 0x03);
        a.J(new byte[] { 0xE9 }, "loop");
        a.Lab("methods");
        Method(a, exp, output, nDeath, output + 0x2000, 0, "m2");
        a.Lab("m2");
        Method(a, exp, output, nMoss, output + 0x2020, 1, "m3");
        a.Lab("m3");
        Method(a, exp, output, nSolid, output + 0x2040, 1, "m4");
        a.Lab("m4");
        MovR11(a, stat);
        a.E(0x41, 0xC7, 0x03, 0x04, 0x00, 0x00, 0x00);
        a.J(new byte[] { 0xE9 }, "detach");
        a.Lab("noimg");
        MovR11(a, stat);
        a.E(0x41, 0xC7, 0x03, 0x02, 0x00, 0x00, 0x00);
        a.J(new byte[] { 0xE9 }, "detach");
        a.Lab("nocls");
        MovR11(a, stat);
        a.E(0x41, 0xC7, 0x03, 0x03, 0x00, 0x00, 0x00);
        a.Lab("detach");
        MovR11(a, output + 8);
        a.E(0x49, 0x8B, 0x0B);
        a.E(0x48, 0x85, 0xC9);
        a.J(new byte[] { 0x0F, 0x84 }, "ret");
        Call(a, exp["mono_thread_detach"]);
        a.Lab("ret");
        a.E(0x31, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3);
        return a.Done();
    }

    private static void Method(Asm a, Dictionary<string, ulong> exp, ulong output, ulong name, ulong slot, int argc, string next)
    {
        MovR11(a, output + 24);
        a.E(0x49, 0x8B, 0x0B);
        MovRdx(a, name);
        a.E(0x41, 0xB8);
        a.E(BitConverter.GetBytes(argc));
        Call(a, exp["mono_class_get_method_from_name"]);
        StoreRax(a, slot);
        a.E(0x48, 0x85, 0xC0);
        a.J(new byte[] { 0x0F, 0x84 }, next);
        a.E(0x48, 0x89, 0xC1);
        Call(a, exp["mono_compile_method"]);
        StoreRax(a, slot + 8);
    }

    private static void Call(Asm a, ulong target)
    {
        a.E(0x48, 0xB8);
        a.E(BitConverter.GetBytes(target));
        a.E(0xFF, 0xD0);
    }

    private static void StoreRax(Asm a, ulong slot)
    {
        MovR11(a, slot);
        a.E(0x49, 0x89, 0x03);
    }

    private static void MovR11(Asm a, ulong value)
    {
        a.E(0x49, 0xBB);
        a.E(BitConverter.GetBytes(value));
    }

    private static void MovRcx(Asm a, ulong value)
    {
        a.E(0x48, 0xB9);
        a.E(BitConverter.GetBytes(value));
    }

    private static void MovRdx(Asm a, ulong value)
    {
        a.E(0x48, 0xBA);
        a.E(BitConverter.GetBytes(value));
    }

    private static void MovR8(Asm a, ulong value)
    {
        a.E(0x49, 0xB8);
        a.E(BitConverter.GetBytes(value));
    }

    private sealed class Asm
    {
        private readonly List<byte> _bytes = new List<byte>();
        private readonly Dictionary<string, int> _labs = new Dictionary<string, int>();
        private readonly List<int> _fixAt = new List<int>();
        private readonly List<string> _fixName = new List<string>();

        public void Lab(string name)
        {
            _labs[name] = _bytes.Count;
        }

        public void E(params byte[] data)
        {
            _bytes.AddRange(data);
        }

        public void J(byte[] op, string name)
        {
            E(op);
            _fixAt.Add(_bytes.Count);
            _fixName.Add(name);
            E(0, 0, 0, 0);
        }

        public byte[] Done()
        {
            byte[] raw = _bytes.ToArray();
            for (int i = 0; i < _fixAt.Count; i++)
            {
                int at = _fixAt[i];
                int rel = _labs[_fixName[i]] - (at + 4);
                byte[] packed = BitConverter.GetBytes(rel);
                Array.Copy(packed, 0, raw, at, 4);
            }
            return raw;
        }
    }
}

internal sealed class Row
{
    public string Name;
    public string Suffix;
    public int Key;
    public Label Live;
    public TextBox Box;
    public CheckBox Freeze;
    public double Frozen;
    public bool IsStats;
    public int StatsKind;
}

internal sealed class TrainerForm : Form
{
    private readonly Label _status;
    private readonly Timer _timer;
    private readonly List<Row> _rows = new List<Row>();
    private IntPtr _process;
    private int _pid;
    private PowerHit _power;
    private StatsHit _stats;
    private int _misses;
    private MonoLayout _layout;
    private ulong _player;
    private CheckBox _god;
    private CheckBox _jumps;
    private CheckBox _dashes;
    private CheckBox _moss;
    private byte[] _deathSaved;
    private byte[] _mossSaved;
    private bool _jumpsSaved;
    private int _savedMaxJumps;
    private byte _savedJumpUnlock;
    private bool _dashSaved;
    private int _savedMaxDashes;
    private byte _savedDashUnlock;
    private Label _speedLive;
    private TextBox _speedBox;
    private CheckBox _speedFreeze;
    private bool _speedHeld;
    private float _savedSpeed = 1f;

    public TrainerForm()
    {
        Text = "IGTAP Power Trainer";
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        ClientSize = new System.Drawing.Size(560, 500);
        Font = new System.Drawing.Font("Segoe UI", 9f);

        _status = new Label();
        _status.Left = 12;
        _status.Top = 10;
        _status.Width = 400;
        _status.Height = 36;
        _status.Text = "Looking for IGTAPfullGame.exe";
        Controls.Add(_status);

        Button refind = new Button();
        refind.Text = "Re-find";
        refind.Left = 430;
        refind.Top = 8;
        refind.Width = 110;
        refind.Click += delegate { Attach(true); };
        Controls.Add(refind);

        AddCurrencyRow(0, "Watts", "w", 0);
        AddCurrencyRow(1, "Green power", "gp", 1);
        AddCurrencyRow(2, "Nuclear power", "np", 2);
        AddCurrencyRow(3, "Clone dust", "cd", 4);
        AddCurrencyRow(4, "Red power", "rp", 5);
        AddCurrencyRow(5, "Blue power", "bp", 6);
        AddStatsRow(6, "Nuclear cap", "np", 0);
        AddStatsRow(7, "Red cap", "rp", 1);
        AddStatsRow(8, "NP boost", "x", 2);

        _god = AddToggle(12, 378, 110, "God mode");
        _jumps = AddToggle(128, 378, 130, "Infinite jumps");
        _dashes = AddToggle(264, 378, 140, "Infinite dashes");
        _moss = AddToggle(410, 378, 140, "Moss as metal");

        Label speedTitle = new Label();
        speedTitle.Text = "Tick speed";
        speedTitle.Left = 12;
        speedTitle.Top = 412;
        speedTitle.Width = 110;
        Controls.Add(speedTitle);
        _speedLive = new Label();
        _speedLive.Left = 122;
        _speedLive.Top = 412;
        _speedLive.Width = 80;
        _speedLive.Text = "-";
        Controls.Add(_speedLive);
        _speedBox = new TextBox();
        _speedBox.Left = 256;
        _speedBox.Top = 408;
        _speedBox.Width = 140;
        _speedBox.Text = "1";
        Controls.Add(_speedBox);
        Button setSpeed = new Button();
        setSpeed.Text = "Set";
        setSpeed.Left = 402;
        setSpeed.Top = 407;
        setSpeed.Width = 52;
        setSpeed.Click += OnSetSpeed;
        Controls.Add(setSpeed);
        _speedFreeze = new CheckBox();
        _speedFreeze.Text = "Freeze";
        _speedFreeze.Left = 460;
        _speedFreeze.Top = 410;
        _speedFreeze.Width = 80;
        Controls.Add(_speedFreeze);

        Label hint = new Label();
        hint.Left = 12;
        hint.Top = 448;
        hint.Width = 530;
        hint.Text = "Box accepts raw numbers or K M G T P suffixes (200T = 200 trillion). Freeze rewrites every tick.";
        Controls.Add(hint);

        _timer = new Timer();
        _timer.Interval = 20;
        _timer.Tick += OnTick;
        _timer.Start();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        BeginInvoke(new Action(delegate { Attach(false); }));
    }

    private void AddCurrencyRow(int index, string name, string suffix, int key)
    {
        AddRow(index, name, suffix, key, false, 0);
    }

    private void AddStatsRow(int index, string name, string suffix, int kind)
    {
        AddRow(index, name, suffix, -1, true, kind);
    }

    private void AddRow(int index, string name, string suffix, int key, bool stats, int kind)
    {
        int y = 52 + index * 36;
        var row = new Row();
        row.Name = name;
        row.Suffix = suffix;
        row.Key = key;
        row.IsStats = stats;
        row.StatsKind = kind;

        Label title = new Label();
        title.Text = name;
        title.Left = 12;
        title.Top = y + 4;
        title.Width = 110;
        Controls.Add(title);

        row.Live = new Label();
        row.Live.Left = 122;
        row.Live.Top = y + 4;
        row.Live.Width = 130;
        row.Live.Text = "-";
        Controls.Add(row.Live);

        row.Box = new TextBox();
        row.Box.Left = 256;
        row.Box.Top = y;
        row.Box.Width = 140;
        Controls.Add(row.Box);

        Button set = new Button();
        set.Text = "Set";
        set.Left = 402;
        set.Top = y - 1;
        set.Width = 52;
        set.Tag = row;
        set.Click += OnSet;
        Controls.Add(set);

        row.Freeze = new CheckBox();
        row.Freeze.Text = "Freeze";
        row.Freeze.Left = 460;
        row.Freeze.Top = y + 2;
        row.Freeze.Width = 80;
        row.Freeze.Tag = row;
        row.Freeze.CheckedChanged += OnFreezeChanged;
        Controls.Add(row.Freeze);

        _rows.Add(row);
    }

    private void OnFreezeChanged(object sender, EventArgs e)
    {
        CheckBox box = (CheckBox)sender;
        Row row = (Row)box.Tag;
        double current;
        if (TryRead(row, out current))
            row.Frozen = current;
    }

    private void OnSet(object sender, EventArgs e)
    {
        Row row = (Row)((Button)sender).Tag;
        Apply(row, true);
    }

    private void Apply(Row row, bool warn)
    {
        double value;
        if (!Format.TryParse(row.Box.Text, out value))
        {
            if (warn)
                _status.Text = "Bad number in " + row.Name + ". Example: 200T or 1.5e12";
            return;
        }
        if (!EnsureAttached())
            return;
        ulong addr = AddressOf(row);
        if (addr == 0)
        {
            if (warn)
                _status.Text = row.Name + " not found. Click Re-find while the POWER panel is open.";
            return;
        }
        if (!WriteDouble(addr, value))
        {
            _status.Text = "Write failed (error " + Marshal.GetLastWin32Error() + ").";
            return;
        }
        row.Frozen = value;
        _status.Text = "Set " + row.Name + " to " + Format.Game(value, row.Suffix);
    }

    private static double BestCurrency(PowerHit hit)
    {
        double best = 0;
        for (int i = 0; i < hit.Value.Length; i++)
        {
            if (hit.Value[i] > best)
                best = hit.Value[i];
        }
        return best;
    }

    private ulong AddressOf(Row row)
    {
        if (!row.IsStats)
        {
            if (_power == null)
                return 0;
            return _power.ValueAddress[row.Key];
        }
        if (_stats == null)
            return 0;
        if (row.StatsKind == 0)
            return _stats.NpCap;
        if (row.StatsKind == 1)
            return _stats.RpCap;
        return _stats.Boost;
    }

    private bool TryRead(Row row, out double value)
    {
        value = 0;
        ulong addr = AddressOf(row);
        if (addr == 0 || _process == IntPtr.Zero)
            return false;
        return ReadDouble(addr, out value);
    }

    private void OnTick(object sender, EventArgs e)
    {
        if (_process == IntPtr.Zero)
            return;
        Process proc;
        try { proc = Process.GetProcessById(_pid); }
        catch { DropProcess("Game closed."); return; }
        if (proc.HasExited)
        {
            DropProcess("Game closed.");
            return;
        }

        if (_power != null && !SignatureOk())
        {
            _misses++;
            if (_misses > 10)
            {
                _power = null;
                _stats = null;
                _status.Text = "Values moved. Click Re-find.";
            }
        }
        else
        {
            _misses = 0;
            UpdateRows();
        }
        ApplyCheats();
    }

    private void UpdateRows()
    {
        for (int i = 0; i < _rows.Count; i++)
        {
            Row row = _rows[i];
            double current;
            if (!TryRead(row, out current))
            {
                row.Live.Text = "-";
                continue;
            }
            if (row.Freeze.Checked)
            {
                WriteDouble(AddressOf(row), row.Frozen);
                current = row.Frozen;
            }
            row.Live.Text = Format.Game(current, row.Suffix);
        }
    }

    private CheckBox AddToggle(int left, int top, int width, string text)
    {
        CheckBox box = new CheckBox();
        box.Left = left;
        box.Top = top;
        box.Width = width;
        box.Text = text;
        Controls.Add(box);
        return box;
    }

    private void ApplyCheats()
    {
        ApplySpeed();
        if (_layout == null || !_layout.Ok)
            return;
        if (_player != 0 && !PlayerAlive())
        {
            _player = 0;
            _jumpsSaved = false;
            _dashSaved = false;
        }
        ApplyGod();
        ApplyJumps();
        ApplyDashes();
        ApplyMoss();
    }

    private void ApplySpeed()
    {
        if (_layout == null || _layout.SpeedAddress == 0)
        {
            _speedLive.Text = "-";
            return;
        }
        float live;
        if (!ReadFloat(_layout.SpeedAddress, out live))
        {
            _speedLive.Text = "-";
            return;
        }
        _speedLive.Text = live.ToString("0.00", CultureInfo.InvariantCulture) + "x";
        if (_speedFreeze.Checked)
        {
            float want;
            if (!TrySpeed(_speedBox.Text, out want))
                return;
            if (!_speedHeld)
            {
                _savedSpeed = live;
                _speedHeld = true;
            }
            WriteFloat(_layout.SpeedAddress, want);
        }
        else if (_speedHeld)
        {
            WriteFloat(_layout.SpeedAddress, _savedSpeed > 0f ? _savedSpeed : 1f);
            _speedHeld = false;
        }
    }

    private void OnSetSpeed(object sender, EventArgs e)
    {
        float want;
        if (!TrySpeed(_speedBox.Text, out want))
        {
            _status.Text = "Tick speed must be between 0.1 and 50. 1 = normal.";
            return;
        }
        if (!EnsureAttached() || _layout == null || _layout.SpeedAddress == 0)
        {
            _status.Text = "Tick speed address not found. Re-find in game.";
            return;
        }
        if (!WriteFloat(_layout.SpeedAddress, want))
        {
            _status.Text = "Tick speed write failed.";
            return;
        }
        _status.Text = "Tick speed set to " + want.ToString("0.##", CultureInfo.InvariantCulture) + "x";
    }

    private static bool TrySpeed(string text, out float value)
    {
        value = 0;
        float n;
        if (text == null || !float.TryParse(text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out n))
            return false;
        if (n < 0.1f || n > 50f)
            return false;
        value = n;
        return true;
    }

    private bool PlayerAlive()
    {
        ulong vt;
        if (!ReadUlong(_player, out vt))
            return false;
        return vt == _layout.Vtable;
    }

    private void ApplyGod()
    {
        if (_layout.OnDeath == 0)
            return;
        if (_god.Checked)
        {
            if (_deathSaved == null)
                _deathSaved = ReadBytes(_layout.OnDeath, 1);
            if (_deathSaved != null && (_deathSaved[0] != 0xC3))
                WriteCode(_layout.OnDeath, new byte[] { 0xC3 });
            if (_player != 0)
            {
                WriteByte(_player + (ulong)_layout.IsDead, 0);
                int cut;
                if (ReadInt(_player + (ulong)_layout.CutsceneMode, out cut) && cut == 2)
                    WriteInt(_player + (ulong)_layout.CutsceneMode, 0);
            }
        }
        else if (_deathSaved != null)
        {
            WriteCode(_layout.OnDeath, _deathSaved);
            _deathSaved = null;
        }
    }

    private void ApplyJumps()
    {
        if (_player == 0)
            return;
        ulong maxAt = _player + (ulong)_layout.MaxAirJumps;
        ulong leftAt = _player + (ulong)_layout.AirJumpsLeft;
        ulong unlockAt = _player + (ulong)_layout.DoubleJumpUnlocked;
        if (_jumps.Checked)
        {
            if (!_jumpsSaved)
            {
                int max;
                byte unlock;
                if (!ReadInt(maxAt, out max) || !ReadByte(unlockAt, out unlock))
                    return;
                _savedMaxJumps = max;
                _savedJumpUnlock = unlock;
                _jumpsSaved = true;
            }
            WriteInt(maxAt, 99);
            WriteInt(leftAt, 99);
            WriteByte(unlockAt, 1);
        }
        else if (_jumpsSaved)
        {
            WriteInt(maxAt, _savedMaxJumps);
            WriteInt(leftAt, _savedMaxJumps);
            WriteByte(unlockAt, _savedJumpUnlock);
            _jumpsSaved = false;
        }
    }

    private void ApplyDashes()
    {
        if (_player == 0)
            return;
        ulong maxAt = _player + (ulong)_layout.MaxAirDashes;
        ulong leftAt = _player + (ulong)_layout.AirDashesLeft;
        ulong unlockAt = _player + (ulong)_layout.DashUnlocked;
        ulong coolAt = _player + (ulong)_layout.DashCooldown;
        if (_dashes.Checked)
        {
            if (!_dashSaved)
            {
                int max;
                byte unlock;
                if (!ReadInt(maxAt, out max) || !ReadByte(unlockAt, out unlock))
                    return;
                _savedMaxDashes = max;
                _savedDashUnlock = unlock;
                _dashSaved = true;
            }
            WriteInt(maxAt, 99);
            WriteInt(leftAt, 99);
            WriteByte(unlockAt, 1);
            WriteFloat(coolAt, -1f);
        }
        else if (_dashSaved)
        {
            WriteInt(maxAt, _savedMaxDashes);
            WriteInt(leftAt, _savedMaxDashes);
            WriteByte(unlockAt, _savedDashUnlock);
            _dashSaved = false;
        }
    }

    private void ApplyMoss()
    {
        if (_moss.Checked)
        {
            if (_layout.Moss != 0 && _layout.Solid != 0)
            {
                if (_mossSaved == null)
                    _mossSaved = ReadBytes(_layout.Moss, 12);
                byte[] jmp = new byte[12];
                jmp[0] = 0x48;
                jmp[1] = 0xB8;
                BitConverter.GetBytes(_layout.Solid).CopyTo(jmp, 2);
                jmp[10] = 0xFF;
                jmp[11] = 0xE0;
                WriteCode(_layout.Moss, jmp);
            }
            if (_player == 0)
                return;
            int ground;
            if (ReadInt(_player + (ulong)_layout.GroundType, out ground) && ground == 1)
                WriteInt(_player + (ulong)_layout.GroundType, 0);
            if (_layout.Sweating > 0)
                WriteByte(_player + (ulong)_layout.Sweating, 0);
            byte onGround;
            byte onWall;
            if (!ReadByte(_player + (ulong)_layout.OnGround, out onGround) || !ReadByte(_player + (ulong)_layout.OnWall, out onWall))
                return;
            if (onGround != 1 && onWall != 1)
                return;
            int maxJ;
            int maxD;
            int maxW;
            if (ReadInt(_player + (ulong)_layout.MaxAirJumps, out maxJ))
                WriteInt(_player + (ulong)_layout.AirJumpsLeft, maxJ);
            if (ReadInt(_player + (ulong)_layout.MaxAirDashes, out maxD))
                WriteInt(_player + (ulong)_layout.AirDashesLeft, maxD);
            if (ReadInt(_player + (ulong)_layout.MaxWallJumps, out maxW))
                WriteInt(_player + (ulong)_layout.WallJumpsLeft, maxW);
            if (_layout.Cling > 0)
                WriteByte(_player + (ulong)_layout.Cling, 0);
        }
        else if (_mossSaved != null && _layout.Moss != 0)
        {
            WriteCode(_layout.Moss, _mossSaved);
            _mossSaved = null;
        }
    }

    private void RestoreCheats()
    {
        if (_process == IntPtr.Zero || _layout == null)
        {
            _deathSaved = null;
            _mossSaved = null;
            _jumpsSaved = false;
            _dashSaved = false;
            return;
        }
        if (_deathSaved != null && _layout.OnDeath != 0)
            WriteCode(_layout.OnDeath, _deathSaved);
        if (_mossSaved != null && _layout.Moss != 0)
            WriteCode(_layout.Moss, _mossSaved);
        if (_player != 0 && _jumpsSaved)
        {
            WriteInt(_player + (ulong)_layout.MaxAirJumps, _savedMaxJumps);
            WriteInt(_player + (ulong)_layout.AirJumpsLeft, _savedMaxJumps);
            WriteByte(_player + (ulong)_layout.DoubleJumpUnlocked, _savedJumpUnlock);
        }
        if (_player != 0 && _dashSaved)
        {
            WriteInt(_player + (ulong)_layout.MaxAirDashes, _savedMaxDashes);
            WriteInt(_player + (ulong)_layout.AirDashesLeft, _savedMaxDashes);
            WriteByte(_player + (ulong)_layout.DashUnlocked, _savedDashUnlock);
        }
        if (_speedHeld && _layout.SpeedAddress != 0)
            WriteFloat(_layout.SpeedAddress, _savedSpeed > 0f ? _savedSpeed : 1f);
        _deathSaved = null;
        _mossSaved = null;
        _jumpsSaved = false;
        _dashSaved = false;
        _speedHeld = false;
    }

    private byte[] ReadBytes(ulong address, int size)
    {
        byte[] buf = new byte[size];
        int read;
        if (!Native.ReadProcessMemory(_process, address, buf, size, out read) || read != size)
            return null;
        return buf;
    }

    private bool WriteBytes(ulong address, byte[] data)
    {
        int written;
        return Native.WriteProcessMemory(_process, address, data, data.Length, out written) && written == data.Length;
    }

    private bool WriteCode(ulong address, byte[] data)
    {
        uint oldProtect;
        if (!Native.VirtualProtectEx(_process, address, (UIntPtr)data.Length, Native.PAGE_EXECUTE_READWRITE, out oldProtect))
            return false;
        bool ok = WriteBytes(address, data);
        uint ignored;
        Native.VirtualProtectEx(_process, address, (UIntPtr)data.Length, oldProtect, out ignored);
        return ok;
    }

    private bool ReadInt(ulong address, out int value)
    {
        value = 0;
        byte[] buf = ReadBytes(address, 4);
        if (buf == null)
            return false;
        value = BitConverter.ToInt32(buf, 0);
        return true;
    }

    private void WriteInt(ulong address, int value)
    {
        WriteBytes(address, BitConverter.GetBytes(value));
    }

    private bool ReadByte(ulong address, out byte value)
    {
        value = 0;
        byte[] buf = ReadBytes(address, 1);
        if (buf == null)
            return false;
        value = buf[0];
        return true;
    }

    private void WriteByte(ulong address, byte value)
    {
        WriteBytes(address, new byte[] { value });
    }

    private bool ReadFloat(ulong address, out float value)
    {
        value = 0;
        byte[] buf = ReadBytes(address, 4);
        if (buf == null)
            return false;
        value = BitConverter.ToSingle(buf, 0);
        return true;
    }

    private bool WriteFloat(ulong address, float value)
    {
        return WriteBytes(address, BitConverter.GetBytes(value));
    }

    private bool ReadUlong(ulong address, out ulong value)
    {
        value = 0;
        byte[] buf = ReadBytes(address, 8);
        if (buf == null)
            return false;
        value = BitConverter.ToUInt64(buf, 0);
        return true;
    }

    private bool SignatureOk()
    {
        byte[] buf = new byte[7 * 24];
        int read;
        if (!Native.ReadProcessMemory(_process, _power.Entry0, buf, buf.Length, out read) || read < buf.Length)
            return false;
        for (int n = 0; n < 7; n++)
        {
            int o = n * 24;
            if (BitConverter.ToInt32(buf, o) != n)
                return false;
            if (BitConverter.ToInt32(buf, o + 4) != -1)
                return false;
            if (BitConverter.ToInt32(buf, o + 8) != n)
                return false;
        }
        return true;
    }

    private void DropProcess(string why)
    {
        RestoreCheats();
        if (_process != IntPtr.Zero)
        {
            Native.CloseHandle(_process);
            _process = IntPtr.Zero;
        }
        _power = null;
        _stats = null;
        _player = 0;
        _layout = null;
        _status.Text = why;
    }

    private bool EnsureAttached()
    {
        if (_process != IntPtr.Zero && _power != null)
            return true;
        Attach(false);
        return _process != IntPtr.Zero && _power != null;
    }

    private void Attach(bool manual)
    {
        UseWaitCursor = true;
        try
        {
            DropProcess("Scanning...");
            Process[] procs = Process.GetProcessesByName("IGTAPfullGame");
            if (procs.Length == 0)
            {
                _status.Text = "IGTAPfullGame.exe is not running.";
                return;
            }
            _pid = procs[0].Id;
            _process = Native.OpenProcess(
                Native.PROCESS_VM_READ | Native.PROCESS_VM_WRITE | Native.PROCESS_VM_OPERATION | Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_CREATE_THREAD,
                false, _pid);
            if (_process == IntPtr.Zero)
            {
                _status.Text = "OpenProcess failed (" + Marshal.GetLastWin32Error() + "). Run the trainer as admin if the game is admin.";
                return;
            }
            _layout = MonoProbe.Resolve(_process);
            MonoProbe.FillSpeed(_process, _layout);
            var powers = new List<PowerHit>();
            var stats = new List<StatsHit>();
            var players = new List<ulong>();
            Scanner.FindAll(_process, powers, stats, _layout, players);
            _player = PickPlayer(players);
            if (powers.Count == 0)
            {
                _status.Text = "Attached, but power block not found. " + CheatNote();
                return;
            }
            _power = powers[0];
            for (int i = 1; i < powers.Count; i++)
            {
                if (BestCurrency(powers[i]) > BestCurrency(_power))
                    _power = powers[i];
            }
            _stats = null;
            if (stats.Count > 0)
            {
                _stats = stats[0];
                for (int i = 1; i < stats.Count; i++)
                {
                    if (stats[i].NpCapValue > _stats.NpCapValue)
                        _stats = stats[i];
                }
            }
            for (int i = 0; i < _rows.Count; i++)
            {
                double v;
                if (TryRead(_rows[i], out v) && !_rows[i].Box.Focused)
                    _rows[i].Box.Text = v.ToString("R", CultureInfo.InvariantCulture);
            }
            float speedNow;
            if (_layout != null && _layout.SpeedAddress != 0 && ReadFloat(_layout.SpeedAddress, out speedNow) && !_speedBox.Focused)
                _speedBox.Text = speedNow.ToString("0.##", CultureInfo.InvariantCulture);
            _status.Text = "Attached PID " + _pid + ". Power block " + _power.Entry0.ToString("X")
                + (_stats == null ? ". Caps not found." : ". Caps found. ")
                + CheatNote();
            if (manual && powers.Count > 1)
                _status.Text += " (" + powers.Count + " matches, using biggest value)";
        }
        finally
        {
            UseWaitCursor = false;
        }
    }

    private ulong PickPlayer(List<ulong> players)
    {
        ulong best = 0;
        int bestScore = -1;
        if (_layout == null)
            return 0;
        for (int i = 0; i < players.Count; i++)
        {
            int maxJ;
            byte unlocked;
            if (!ReadInt(players[i] + (ulong)_layout.MaxAirJumps, out maxJ))
                continue;
            if (!ReadByte(players[i] + (ulong)_layout.DoubleJumpUnlocked, out unlocked))
                unlocked = 0;
            int score = maxJ * 2 + unlocked;
            if (score > bestScore)
            {
                bestScore = score;
                best = players[i];
            }
        }
        return best;
    }

    private string CheatNote()
    {
        if (_layout == null || !_layout.Ok)
            return "Player fields missing" + (_layout != null && _layout.Error != null ? " (" + _layout.Error + ")." : ".");
        string note = _player == 0 ? "Player not found." : "Player " + _player.ToString("X") + ".";
        if (_layout.SpeedAddress == 0)
            note += " Tick speed missing.";
        return note;
    }

    private bool ReadDouble(ulong address, out double value)
    {
        value = 0;
        byte[] buf = new byte[8];
        int read;
        if (!Native.ReadProcessMemory(_process, address, buf, 8, out read) || read != 8)
            return false;
        value = BitConverter.ToDouble(buf, 0);
        return true;
    }

    private bool WriteDouble(ulong address, double value)
    {
        byte[] buf = BitConverter.GetBytes(value);
        int written;
        return Native.WriteProcessMemory(_process, address, buf, 8, out written) && written == 8;
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _timer.Stop();
        RestoreCheats();
        if (_process != IntPtr.Zero)
            Native.CloseHandle(_process);
        base.OnFormClosed(e);
    }
}

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--dump")
        {
            Dump();
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrainerForm());
    }

    private static void Dump()
    {
        string path = Path.Combine(Path.GetTempPath(), "igtap-trainer-dump.txt");
        Process[] procs = Process.GetProcessesByName("IGTAPfullGame");
        if (procs.Length == 0)
        {
            File.WriteAllText(path, "no process");
            return;
        }
        IntPtr h = Native.OpenProcess(
            Native.PROCESS_VM_READ | Native.PROCESS_VM_WRITE | Native.PROCESS_VM_OPERATION | Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_CREATE_THREAD,
            false, procs[0].Id);
        if (h == IntPtr.Zero)
        {
            File.WriteAllText(path, "open failed " + Marshal.GetLastWin32Error());
            return;
        }
        var sb = new System.Text.StringBuilder();
        MonoLayout layout = MonoProbe.Resolve(h);
        MonoProbe.FillSpeed(h, layout);
        var powers = new List<PowerHit>();
        var stats = new List<StatsHit>();
        var players = new List<ulong>();
        Scanner.FindAll(h, powers, stats, layout, players);
        sb.AppendLine("layout ok " + layout.Ok + " err " + layout.Error);
        sb.AppendLine("vtable " + layout.Vtable.ToString("X") + " inst " + layout.InstanceSize + " player " + (players.Count > 0 ? players[0].ToString("X") : "none") + " players " + players.Count);
        sb.AppendLine("ondeath " + layout.OnDeath.ToString("X") + " moss " + layout.Moss.ToString("X") + " solid " + layout.Solid.ToString("X"));
        sb.AppendLine("speed " + layout.SpeedAddress.ToString("X"));
        sb.AppendLine("power hits " + powers.Count);
        for (int i = 0; i < powers.Count; i++)
        {
            PowerHit p = powers[i];
            sb.AppendLine("entry " + p.Entry0.ToString("X"));
            for (int k = 0; k < 7; k++)
                sb.AppendLine("  " + k + " " + p.ValueAddress[k].ToString("X") + " " + p.Value[k].ToString("R", CultureInfo.InvariantCulture) + " " + Format.Game(p.Value[k], ""));
        }
        sb.AppendLine("stats hits " + stats.Count);
        for (int i = 0; i < Math.Min(stats.Count, 8); i++)
        {
            StatsHit s = stats[i];
            sb.AppendLine("base " + s.Base.ToString("X") + " cap " + s.NpCapValue.ToString("R", CultureInfo.InvariantCulture) + " rp " + s.RpCapValue.ToString("R") + " boost " + s.BoostValue.ToString("R"));
        }
        Native.CloseHandle(h);
        File.WriteAllText(path, sb.ToString());
    }
}
