// FTDI/USB Logger — независимый лаунчер (один .exe, без cmd/PowerShell).
//
// Что делает:
//   1) показывает логотип (splash.png встроен в ресурсы) ровно 2 секунды;
//   2) если движок ещё не запущен — стартует ftdi-logger.exe с этим каталогом
//      как --root (движок наследует права администратора от лаунчера);
//   3) ждёт /api/health (до 60 с) и открывает UI в окне Edge (--app), но уже
//      без прав администратора — через Shell.Application (Explorer де-элевирует);
//   4) закрывает splash и выходит.
//
// Права администратора запрашиваются манифестом (app.manifest, requireAdministrator):
// движку они нужны для Frida-хуков и чтения чужих процессов.
//
// Сборка: scripts\build-launcher.ps1 (csc из .NET Framework 4.x, есть в Windows).
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace FtdiLoggerLauncher
{
    internal static class Program
    {
        private const string DefaultPort = "7811";
        private const int SplashMinMs = 2000;
        private const int HealthWaitMs = 60000;

        internal static string RootDir;
        internal static string Port;

        [STAThread]
        private static void Main(string[] args)
        {
            RootDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd('\\');
            Port = Environment.GetEnvironmentVariable("FTDI_LOGGER_PORT");
            if (string.IsNullOrEmpty(Port)) Port = DefaultPort;
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--port") Port = args[i + 1];
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            SplashForm splash = new SplashForm();
            Thread worker = new Thread(new ParameterizedThreadStart(Boot));
            worker.IsBackground = true;
            worker.Start(splash);
            Application.Run(splash);
        }

        /// <summary>Фон: поднять движок, дождаться health, открыть UI, закрыть splash.</summary>
        private static void Boot(object state)
        {
            SplashForm splash = (SplashForm)state;
            DateTime started = DateTime.UtcNow;
            try
            {
                EnsureDesktopShortcut();
                bool already = HealthOk(700);
                if (!already)
                {
                    splash.SetStatus("Запуск движка…");
                    if (!StartEngine(splash))
                    {
                        return;
                    }
                }
                else
                {
                    splash.SetStatus("Уже запущен, открываю окно…");
                }

                DateTime deadline = DateTime.UtcNow.AddMilliseconds(HealthWaitMs);
                bool ok = already;
                while (!ok && DateTime.UtcNow < deadline)
                {
                    ok = HealthOk(500);
                    if (!ok) Thread.Sleep(200);
                }

                // Логотип должен «гореть» ровно 2 секунды — даже если движок поднялся раньше.
                int elapsed = (int)(DateTime.UtcNow - started).TotalMilliseconds;
                if (elapsed < SplashMinMs) Thread.Sleep(SplashMinMs - elapsed);

                if (!ok)
                {
                    splash.ShowError("Движок не ответил за 60 с. Смотрите logger.err.log рядом с программой.");
                    return;
                }

                splash.SetStatus("Открываю интерфейс…");
                OpenUi(splash);
                Thread.Sleep(300);
                splash.CloseSafe();
            }
            catch (Exception ex)
            {
                splash.ShowError("Ошибка запуска: " + ex.Message);
            }
        }

        /// <summary>Проверка /api/health без прокси и без внешних зависимостей.</summary>
        internal static bool HealthOk(int timeoutMs)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + Port + "/api/health");
                req.Proxy = null;
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                {
                    return (int)res.StatusCode == 200;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Старт ftdi-logger.exe с логами в файлы; движок наследует админ-права.</summary>
        private static bool StartEngine(SplashForm splash)
        {
            string exe = Path.Combine(RootDir, "ftdi-logger.exe");
            if (!File.Exists(exe))
            {
                splash.ShowError("Не найден ftdi-logger.exe рядом с лаунчером.");
                return false;
            }
            string outLog = Path.Combine(RootDir, "logger.out.log");
            string errLog = Path.Combine(RootDir, "logger.err.log");
            string cli = "\"\"" + exe + "\" --root \"" + RootDir + "\" --port " + Port +
                         " >> \"" + outLog + "\" 2>> \"" + errLog + "\"\"";
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cli);
            psi.WorkingDirectory = RootDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            try
            {
                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                splash.ShowError("Не удалось запустить движок: " + ex.Message);
                return false;
            }
        }

        /// <summary>Путь к рабочему столу: реестр оболочки (переживает OneDrive-редирект).</summary>
        private static string DesktopDir()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
                {
                    string value = key == null ? null : key.GetValue("Desktop") as string;
                    if (!string.IsNullOrEmpty(value))
                    {
                        value = Environment.ExpandEnvironmentVariables(value);
                        if (Directory.Exists(value)) return value;
                    }
                }
            }
            catch
            {
                // ниже — стандартный путь
            }
            return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        }

        /// <summary>
        /// Ярлык на рабочем столе при первом запуске. Установщик создаёт его сам,
        /// но на OneDrive-профилях shell-константа {autodesktop} не раскрывается,
        /// поэтому лаунчер достраивает ярлык (иконка — assets/app.ico).
        /// </summary>
        private static void EnsureDesktopShortcut()
        {
            try
            {
                string desktop = DesktopDir();
                if (string.IsNullOrEmpty(desktop)) return;
                string link = Path.Combine(desktop, "FTDI USB Logger.lnk");
                if (File.Exists(link)) return;

                string exe = Path.Combine(RootDir, "FTDI_USB_Logger.exe");
                string icon = Path.Combine(RootDir, "app.ico");
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return;
                object shell = Activator.CreateInstance(shellType);
                object shortcut = shellType.InvokeMember(
                    "CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { link });
                Type shortcutType = shortcut.GetType();
                shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { exe });
                shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { RootDir });
                if (File.Exists(icon))
                {
                    shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { icon });
                }
                shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "FTDI/USB Logger" });
                shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
            }
            catch
            {
                // Ярлык — не критичная часть запуска: без него приложение работает.
            }
        }

        /// <summary>Открыть UI: окно Edge (--app) в обычном, неадминском контексте.</summary>
        private static void OpenUi(SplashForm splash)
        {
            if (Environment.GetEnvironmentVariable("FTDI_LOGGER_NO_OPEN") == "1") return;
            string url = "http://127.0.0.1:" + Port + "/";
            string edge = FindEdge();
            if (edge != null)
            {
                if (ShellExecute(edge, "--app=" + url)) return;
                try
                {
                    Process.Start(edge, "--app=" + url);
                    return;
                }
                catch { }
            }
            // Нет Edge — открываем URL браузером по умолчанию (тоже через Explorer).
            if (!ShellExecute(url, ""))
            {
                try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
                catch (Exception ex) { splash.ShowError("Не удалось открыть браузер: " + ex.Message); }
            }
        }

        /// <summary>Запуск через Shell.Application: Explorer выполняет запрос в обычном (среднем) IL.</summary>
        private static bool ShellExecute(string file, string arguments)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("Shell.Application");
                if (shellType == null) return false;
                object shell = Activator.CreateInstance(shellType);
                shellType.InvokeMember(
                    "ShellExecute",
                    BindingFlags.InvokeMethod,
                    null,
                    shell,
                    new object[] { file, arguments, "", "open", 1 });
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string FindEdge()
        {
            string[] candidates = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft\\Edge\\Application\\msedge.exe"),
            };
            foreach (string path in candidates)
            {
                if (File.Exists(path)) return path;
            }
            return null;
        }
    }

    /// <summary>Безрамочное окно с логотипом; закрывается из фонового потока.</summary>
    internal sealed class SplashForm : Form
    {
        private readonly Label status;
        private readonly PictureBox picture;

        internal SplashForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(11, 14, 18);
            TopMost = true;
            ShowInTaskbar = false;
            DoubleBuffered = true;

            Image logo = LoadLogo();
            int width = 520;
            int height = 160;
            if (logo != null)
            {
                double scale = Math.Min(1.0, 760.0 / logo.Width);
                int w = (int)(logo.Width * scale);
                int h = (int)(logo.Height * scale);
                width = Math.Max(w + 24, 520);
                height = h + 70;
                picture = new PictureBox();
                picture.Image = logo;
                picture.SizeMode = PictureBoxSizeMode.Zoom;
                picture.SetBounds(12, 12, w, h);
                Controls.Add(picture);
            }
            ClientSize = new Size(width, height);

            status = new Label();
            status.Text = "Запуск FTDI/USB Logger…";
            status.ForeColor = Color.FromArgb(210, 220, 230);
            status.Font = new Font("Segoe UI", 10f);
            status.TextAlign = ContentAlignment.MiddleCenter;
            status.SetBounds(12, ClientSize.Height - 46, ClientSize.Width - 24, 32);
            Controls.Add(status);

            MouseClick += delegate { Close(); };
        }

        private static Image LoadLogo()
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                using (Stream stream = assembly.GetManifestResourceStream("SplashImage"))
                {
                    if (stream == null) return null;
                    // Копируем в память: Image.FromStream не должен зависеть от потока ресурса.
                    using (MemoryStream buffered = new MemoryStream())
                    {
                        stream.CopyTo(buffered);
                        buffered.Position = 0;
                        return Image.FromStream(buffered);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        internal void SetStatus(string text)
        {
            RunOnUi(delegate
            {
                status.Text = text;
                status.ForeColor = Color.FromArgb(210, 220, 230);
            });
        }

        internal void ShowError(string text)
        {
            RunOnUi(delegate
            {
                status.Text = text;
                status.ForeColor = Color.FromArgb(255, 150, 150);
            });
        }

        internal void CloseSafe()
        {
            RunOnUi(delegate { Close(); });
        }

        private void RunOnUi(Action action)
        {
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke(action);
            }
            catch
            {
                // Окно уже закрыто — молча выходим.
            }
        }
    }
}
