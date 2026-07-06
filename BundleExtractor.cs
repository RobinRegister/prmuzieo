using System;
using System.IO;
using System.Text;

class BundleExtractor {
    static void Main(string[] args) {
        string exePath = args.Length > 0 ? args[0] : "jqone.exe";
        if (!File.Exists(exePath)) { Console.WriteLine($"File not found: {exePath}"); return; }
        var data = File.ReadAllBytes(exePath);
        Console.WriteLine($"[+] Loaded {data.Length} bytes");

        for (int i = data.Length - 32; i > data.Length - 256 * 1024 && i > 0; i--) {
            if (data[i] == 0x55 && data[i+1] == 0x43 && data[i+2] == 0x02 && data[i+3] == 0x00) {
                Console.WriteLine($"[+] Bundle marker at offset {i}");
                long manifestOffset = BitConverter.ToInt64(data, i - 8);
                Console.WriteLine($"[+] Manifest at offset {manifestOffset}");

                try {
                    using (var ms = new MemoryStream(data, (int)manifestOffset, (int)(i - 8 - manifestOffset)))
                    using (var r = new BinaryReader(ms, Encoding.UTF8)) {
                        int major = r.ReadInt32();
                        int minor = r.ReadInt32();
                        int numFiles = r.ReadInt32();
                        string bundleId = r.ReadString();
                        
                        if (numFiles <= 0 || numFiles > 500) {
                            Console.WriteLine($"Invalid file count: {numFiles}, trying next...");
                            continue;
                        }
                        
                        Console.WriteLine($"Bundle v{major}.{minor}, {numFiles} files, id={bundleId}");
                        Directory.CreateDirectory("extracted_asm");

                        for (int f = 0; f < numFiles; f++) {
                            long off = r.ReadInt64();
                            long sz = r.ReadInt64();
                            if (r.BaseStream.Position >= r.BaseStream.Length) break;
                            string name = r.ReadString();
                            
                            string fileName = Path.GetFileName(name);
                            if (string.IsNullOrEmpty(fileName)) fileName = $"file_{f}.dll";
                            string outPath = Path.Combine("extracted_asm", fileName);
                            
                            if (off > 0 && sz > 0 && off + sz <= data.Length) {
                                File.WriteAllBytes(outPath, data.Skip((int)off).Take((int)sz).ToArray());
                                Console.WriteLine($"  [{f}] {name} → {fileName} ({sz}B)");
                            }
                        }
                    }
                    return;
                } catch (Exception ex) {
                    Console.WriteLine($"Parse error: {ex.Message}");
                    continue;
                }
            }
        }
        Console.WriteLine("[-] No bundle marker found");
    }
}
