using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Program {
    static void Main(string[] args) {
        string dllPath = null;
        var dirs = new[] { @"..\deobfuscated", @"..\extracted", @"." };
        foreach (var d in dirs) {
            if (Directory.Exists(d)) {
                var dlls = Directory.GetFiles(d, "*.dll").OrderByDescending(f => new FileInfo(f).Length).ToArray();
                if (dlls.Length > 0) { dllPath = dlls[0]; break; }
            }
        }
        if (args.Length > 0 && File.Exists(args[0])) dllPath = args[0];

        Console.WriteLine($"[+] Loading: {dllPath}");
        if (!File.Exists(dllPath)) { Console.WriteLine("[-] No DLL found"); return; }

        var mod = ModuleDefMD.Load(dllPath);
        int patches = 0;

        foreach (var type in mod.GetTypes()) {
            foreach (var method in type.Methods) {
                if (!method.HasBody) continue;
                var body = method.Body;
                var fullName = $"{type.FullName}.{method.Name}";
                bool patched = false;

                // Pattern 1: Methods returning bool with crypto calls (VerifySignature)
                if (method.ReturnType.FullName == "System.Boolean" && method.Parameters.Count <= 2) {
                    bool hasCrypto = body.Instructions.Any(i =>
                        i.OpCode == OpCodes.Call && i.Operand != null &&
                        (i.Operand.ToString().Contains("Verify") ||
                         i.Operand.ToString().Contains("Crypto") ||
                         i.Operand.ToString().Contains("Signature") ||
                         i.Operand.ToString().Contains("BouncyCastle") ||
                         i.Operand.ToString().Contains("ECDsa") ||
                         i.Operand.ToString().Contains("DSA")));
                    if (hasCrypto) {
                        Console.WriteLine($"[!] PATCH VerifySig: {fullName}");
                        patched = true;
                    }
                }

                // Pattern 2: Methods with "register"/"valid"/"license" in name returning bool
                if (!patched && method.ReturnType.FullName == "System.Boolean") {
                    string lower = fullName.ToLower();
                    if (lower.Contains("register") || lower.Contains("valid") ||
                        lower.Contains("license") || lower.Contains("expir")) {
                        Console.WriteLine($"[!] PATCH BoolCheck: {fullName}");
                        patched = true;
                    }
                }

                // Pattern 3: Methods calling DateTime.Now or DateTime.UtcNow and returning bool
                if (!patched && method.ReturnType.FullName == "System.Boolean") {
                    bool hasDateTime = body.Instructions.Any(i =>
                        i.OpCode == OpCodes.Call && i.Operand != null &&
                        (i.Operand.ToString().Contains("DateTime") ||
                         i.Operand.ToString().Contains("get_Now") ||
                         i.Operand.ToString().Contains("get_UtcNow")));
                    if (hasDateTime && patches < 10) {
                        Console.WriteLine($"[!] PATCH DateTimeCheck: {fullName}");
                        patched = true;
                    }
                }

                if (patched) {
                    body.Instructions.Clear();
                    body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    body.Variables.Clear();
                    body.ExceptionHandlers.Clear();
                    patches++;
                }
            }
        }

        if (patches > 0) {
            string outPath = Path.ChangeExtension(dllPath, null) + "_cracked.dll";
            mod.Write(outPath);
            Console.WriteLine($"[+] Done: {patches} methods → {outPath}");
        } else {
            Console.WriteLine("[-] No targets. Dumping all bool-returning methods:");
            foreach (var type in mod.GetTypes().Take(100)) {
                foreach (var m in type.Methods.Where(m2 => m2.HasBody && m2.ReturnType.FullName == "System.Boolean")) {
                    Console.WriteLine($"  {type.FullName}.{m.Name}()  params={m.Parameters.Count}");
                }
            }
        }
    }
}
