using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

class Program {
    static void Main(string[] args) {
        string dllPath = args.Length > 0 ? args[0] : null;
        
        if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath)) {
            var d = "..\\extracted";
            if (Directory.Exists(d)) {
                var dlls = Directory.GetFiles(d, "*.dll").OrderByDescending(f => new FileInfo(f).Length).ToArray();
                if (dlls.Length > 0) dllPath = dlls[0];
            }
        }
        
        if (!File.Exists(dllPath)) { Console.WriteLine("[-] No DLL"); return; }
        Console.WriteLine($"[+] Loading: {Path.GetFileName(dllPath)} ({new FileInfo(dllPath).Length} bytes)");

        ModuleDefMD mod;
        try { mod = ModuleDefMD.Load(dllPath); }
        catch (Exception ex) { Console.WriteLine($"[-] Load failed: {ex.Message}"); return; }

        int patches = 0;
        int scanned = 0;
        
        // Collect ALL types, including nested
        var allTypes = mod.GetTypes().ToList();
        Console.WriteLine($"[*] Scanning {allTypes.Count} types...");

        foreach (var type in allTypes) {
            foreach (var method in type.Methods.ToList()) {
                if (!method.HasBody) continue;
                scanned++;
                
                var body = method.Body;
                var fullName = $"{type.FullName}.{method.Name}";
                bool patch = false;
                string reason = "";

                // STRATEGY 1: Find methods returning bool with specific call patterns
                if (method.ReturnType.FullName == "System.Boolean") {
                    foreach (var ins in body.Instructions) {
                        if (ins.OpCode == OpCodes.Call && ins.Operand != null) {
                            var callee = ins.Operand.ToString();
                            string cl = callee.ToLower();
                            
                            // License/crypto verification calls
                            if (cl.Contains("verify") && (cl.Contains("signature") || cl.Contains("data") || cl.Contains("hash"))) {
                                patch = true; reason = "VerifySignature call"; break;
                            }
                            if (cl.Contains("bouncycastle") || cl.Contains("ecdsa") || cl.Contains("dsa")) {
                                patch = true; reason = "BouncyCastle/ECDSA call"; break;
                            }
                            if (cl.Contains("datetime") && (cl.Contains("now") || cl.Contains("utcnow"))) {
                                // DateTime comparison methods that return bool — likely expiry checks
                                bool hasComparison = body.Instructions.Any(i2 => 
                                    i2.OpCode == OpCodes.Clt || i2.OpCode == OpCodes.Cgt || 
                                    i2.OpCode == OpCodes.Blt || i2.OpCode == OpCodes.Bgt ||
                                    i2.OpCode == OpCodes.Ble || i2.OpCode == OpCodes.Bge ||
                                    i2.OpCode == OpCodes.Ceq);
                                if (hasComparison) {
                                    patch = true; reason = "DateTime comparison"; break;
                                }
                            }
                            if ((cl.Contains("license") || cl.Contains("licence")) && 
                                (cl.Contains("valid") || cl.Contains("check") || cl.Contains("verify") || cl.Contains("is"))) {
                                patch = true; reason = "License validity check"; break;
                            }
                        }
                    }
                }

                // STRATEGY 2: Methods with certain names that return bool
                if (!patch && method.ReturnType.FullName == "System.Boolean") {
                    string nl = method.Name.String.ToLower();
                    string tl = type.FullName.ToLower();
                    if ((nl.Contains("valid") || nl.Contains("register") || nl.Contains("license") || 
                         nl.Contains("expir") || nl.Contains("trial") || nl.Contains("activated")) &&
                        method.Parameters.Count <= 2) {
                        patch = true; reason = "Name pattern match";
                    }
                    if (tl.Contains("license") && tl.Contains("manager") && method.Parameters.Count <= 2) {
                        patch = true; reason = "License manager method";
                    }
                }

                // STRATEGY 3: Any method that reads from a file/registry and returns bool
                if (!patch && method.ReturnType.FullName == "System.Boolean") {
                    bool readsFile = body.Instructions.Any(i =>
                        i.OpCode == OpCodes.Call && i.Operand != null &&
                        (i.Operand.ToString().Contains("File.") || 
                         i.Operand.ToString().Contains("Registry") ||
                         i.Operand.ToString().Contains("ReadAll")));
                    if (readsFile && method.Parameters.Count <= 2) {
                        patch = true; reason = "File/Registry read returning bool";
                    }
                }

                if (patch) {
                    Console.WriteLine($"  PATCH [{reason}] {fullName}");
                    body.Instructions.Clear();
                    body.Instructions.Add(OpCodes.Ldc_I4_1.ToInstruction());
                    body.Instructions.Add(OpCodes.Ret.ToInstruction());
                    body.Variables.Clear();
                    body.ExceptionHandlers.Clear();
                    patches++;
                    
                    if (patches >= 20) break;
                }
            }
            if (patches >= 20) break;
        }

        Console.WriteLine($"[*] Scanned {scanned} methods, patched {patches}");
        
        if (patches > 0) {
            string outPath = Path.ChangeExtension(dllPath, null) + "_cracked.dll";
            try {
                mod.Write(outPath);
                Console.WriteLine($"[+] Saved {outPath}");
            } catch (Exception ex) {
                Console.WriteLine($"[-] Write failed: {ex.Message}");
            }
        } else {
            Console.WriteLine("[-] No patch targets found");
            // Dump ALL bool-returning methods for manual analysis
            Console.WriteLine("\n=== ALL bool-returning methods ===");
            int dumped = 0;
            foreach (var type in allTypes) {
                foreach (var method in type.Methods) {
                    if (!method.HasBody || method.ReturnType.FullName != "System.Boolean") continue;
                    Console.WriteLine($"  {type.FullName}.{method.Name}({method.Parameters.Count} params)");
                    dumped++;
                    if (dumped >= 50) break;
                }
                if (dumped >= 50) break;
            }
        }
    }
}
