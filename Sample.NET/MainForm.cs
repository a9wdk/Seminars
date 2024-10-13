using System;
using System.Threading;
using System.Windows.Forms;

using Aladdin.HASP.Envelope;
using Aladdin.HASP.EnvelopeRuntime;

namespace Test_sample {

    public partial class MainForm : Form {

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //   
        // В случае, если при вызове защищенного метода отсутствует необходимая лицензия, код защиты выдает MessageBox с
        // кодом ошибки и, при его закрытии, повторно пытается получить доступ к лицензии. Если лицензии нет и не предвидится,
        // возникает ситуация, схожая с deadlock'ом - будет постоянно висеть модальный MessageBox, не давая работать.
        // Управлять реакцией кода защиты на такие ситуации можно через специальную процедуру - NotificationDelegat-обработчик.
        // NotificationDelegat-обработчик вызывается каждый раз, когда при вызове защищенного метода отсутствует ключ или
        // необходимая для работы метода лицензия. В качестве параметра обработчик получает код возврата Sentinel LDK API,
        // указывающий на причину ошибки. Обработчик может предпринять некоторые действия, зависящие от ошибки, а так же,
        // решить, что делать дальше. Возможные варианты:
        // 
        //      StatusAlertAndRetry     - Вариант, принятый по умолчанию. Передать управление коду защиты (выдаёт MessageBox
        //                                c кодом ошибки), после чего повторить проверку лицензии.
        //      StatusRetry             - Немедленно повторить проверку лицензии без передачи управления коду защиты
        //      StatusReturnNothing     - Прервать выполнение защищенного кода, ничего более не делая.
        //      StatusThrowException    - Прервать выполнение защищенного кода, возбудив исключение.

        // Флаг, указывающий, использовать или нет NotificationDelegat-обработчик для обработки ошибок 
        private bool m_NotificationsEnabled = true;

        // Реакция на нештатную ситуацию
        private static EnvelopeRuntimeStatus m_Status = EnvelopeRuntimeStatus.StatusReturnNothing;

        // Сообщение об ошибке, формируемое NotificationDelegat-обработчиком
        private static string ApiError;    
         
        // Назначение процедуры Handler как NotificationDelegat-обработчика
        private NotificationDelegate m_NotificationDelegate = new NotificationDelegate(Handler);

        // NotificationDelegat-обработчик, получающий управление при нештатных ситуациях, связанных с защитой.
        public static EnvelopeRuntimeStatus Handler(int haspStatus) {
            ApiError = "Sentinel LDK API error = " + haspStatus + "\n";
            MessageBox.Show(ApiError, "NotificationDelegate Handler", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return m_Status;
        }

        public MainForm() {
            InitializeComponent();

            SetStyle(ControlStyles.DoubleBuffer, true);
            SetStyle(ControlStyles.UserPaint, true);
            SetStyle(ControlStyles.AllPaintingInWmPaint, true);

            // Заполняем заголовок окна данными из атрибутов сборки
            var header = new AboutBox();
            base.Text = header.AssemblyTitle  + " - " + header.AssemblyDescription;

            // Инициализация некоторых полей
            _RtfHead = GetRtfHeader();
            _BoxCapacity = CalcTextBoxCapacity();
        }


        #region Обработчики, обеспечивающие фукционал меню главной формы 

        // Выход
        void Menu_Exit(object sender, EventArgs e) {
            Environment.Exit(0);
        }

        // Вызов формы About
        void Menu_About(object sender, EventArgs e) {
            new AboutBox().ShowDialog();
        }

        // Запуск функции Function1
        void Menu_Start_F1(object sender, EventArgs e) {

            // Установка NotificationDelegat-обработчика
            if (m_NotificationsEnabled) EnvelopeRuntimeEvent.Instance.Notification += m_NotificationDelegate;

            try {
                Start_F1();
            } catch (Exception exc) {
                    ApiError += "\n" + exc.ToString();
                    MessageBox.Show(ApiError, "Exception Handler", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            // Снятие NotificationDelegat-обработчика
            if (m_NotificationsEnabled) EnvelopeRuntimeEvent.Instance.Notification -= m_NotificationDelegate;
        }

        // Остановка функции Function1
        void Menu_Stop_F1(object sender, EventArgs e) {
            start_F1_MenuItem.Enabled = true;
            stop_F1_MenuItem.Enabled = false;
            _F1_Terminate_Flag = true;
        }

        // Запуск функции Function2
        void Menu_Start_F2(object sender, EventArgs e) {
            start_F2_MenuItem.Enabled = false;
            stop_F2_MenuItem.Enabled = true;
            _F2_Terminate_Flag = false;
            var tF2 = new Thread(Function2) { IsBackground = true };
            tF2.Start();
        }

        // Остановка функции Function2
        void Menu_Stop_F2(object sender, EventArgs e) {
            start_F2_MenuItem.Enabled = true;
            stop_F2_MenuItem.Enabled = false;
            _F2_Terminate_Flag = true;
        }

        #endregion

        #region Реализация методов Function1 и Function2 

        // NotificationDelegat-обработчик получает управление только в случае возникновения проблем в методах, 
        // вызываемых в текущем потоке. Т.к. Function1 запускается как отдельный поток, обработчик не сможет
        // перехватить управление при возникновении проблем с защитой, и в потоке будет использована реакция
        // по умолчанию (StatusAlertAndRetry). Для перехвата управления необходимо защитить код, запускающий
        // поток с Function1 так же, как и саму Function1. Поскольку этод код будет выполняться в текущем
        // потоке, в случае проблем с лицензией управление будет перехвачено до передачи в Function1.
        
        [EnvelopeMethodProtectionAttributes(
            Protect           = true, 
            FeatureId         = 1,
            Encrypt           = true,
            CodeObfuscation   = false,
            Frequency         = EnvelopeMethodProtectionFrequency.CheckEveryTime,
            SymbolObfuscation = EnvelopeSymbolObfuscation.ObfuscateDefault)]

        void Start_F1() {
            start_F1_MenuItem.Enabled = false;
            stop_F1_MenuItem.Enabled = true;
            _F1_Terminate_Flag = false;
            var tF1 = new Thread(Function1) { IsBackground = true };
            tF1.Start();
        }

        //  Процедура генерирует псевдо-случайные числа в диапазоне [0;127] с контролем ошибок.
        //  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным.
        //  Так же, в процедуре реализована реакция на "редкое событие" - три одинаковых 
        //  числа подряд, последнее из них выводится синим цветом.

       [EnvelopeMethodProtectionAttributes(
            Protect           = true,
            FeatureId         = 1,
            Encrypt           = false,
            CodeObfuscation   = true,
            Frequency         = EnvelopeMethodProtectionFrequency.CheckEveryTime,
            SymbolObfuscation = EnvelopeSymbolObfuscation.ObfuscateDefault)]

       void Function1() {
            const int zMin = 0x0000, zMax = 0x0080, zXor = 0xFF00, zAnd = 0x00FF;
            int z0, z1 = 0x11, z2 = 0x22;
            
            var rnd = new Random();
            while(!_F1_Terminate_Flag) {
                var delay = ConstantProvider.Delay;
                var buff = _RtfHead;
                for (var i = 0; i < _BoxCapacity; i++) {
                    z0 = (rnd.Next(zMax - zMin) + zMin) ^ (zXor & zAnd);

                    // Проверка на редкое событие
                    if (z1 == z0 && z2 == z0) {
                        delay = ConstantProvider.RareCaseDelay;
                        buff += ConstantProvider.RtfBlue;
                    } else buff += (z0 < 128) ? ConstantProvider.RtfGreen : ConstantProvider.RtfRed;
                    
                    buff += string.Format("{0:X4}h\xA0", z0);
                    z2 = z1;
                    z1 = z0;
                }
                buff += ConstantProvider.RtfTail;
                
                Action action = () => rTB1.Rtf = buff;
                rTB1.Invoke(action);
                Thread.Sleep(delay);
            }
        }

        //  Процедура генерирует псевдо-случайные числа в диапазоне [128; 255] с контролем ошибок.
        //  Все входящие в диапазон значения выводятся зеленым цветом, все прочие - красным. Так же, 
        //  в процедуре реализована реакция на "редкое событие" - монотонно возрастающая последовательность
        //  из трёх чисел подряд, отличающиеся друг от друга на единицу, последнее из них выводится синим цветом.

        [EnvelopeMethodProtectionAttributes(
            Protect           = true,
            FeatureId         = 2,
            Encrypt           = false,
            CodeObfuscation   = false,
            Frequency         = EnvelopeMethodProtectionFrequency.CheckEveryTime,
            SymbolObfuscation = EnvelopeSymbolObfuscation.ObfuscateDefault  )]

        void Function2() {
            const int zMin = 0x0080, zMax = 0x00FF, zXor = 0xFF00, zAnd = 0x00FF;
            int z0, z1 = 0x11, z2 = 0x22;

            var rnd = new Random();
            while (!_F2_Terminate_Flag) {
                var delay = ConstantProvider.Delay;
                var buff = _RtfHead;
                for (var i = 0; i < _BoxCapacity; i++) {
                    z0 = (rnd.Next(zMax - zMin) + zMin) ^ (zXor & zAnd);

                    // Проверка на редкое событие
                    if (z1 == z0 - 1 && z2 == z1 - 1) {
                        delay = ConstantProvider.RareCaseDelay;
                        buff += ConstantProvider.RtfBlue;
                    } else buff += (z0 > 127 && z0 < 256) ? ConstantProvider.RtfGreen : ConstantProvider.RtfRed;  

                    buff += string.Format("{0:X4}h\xA0", z0);
                    z2 = z1;
                    z1 = z0;
                }
                buff += ConstantProvider.RtfTail;
               
                Action action = () => rTB2.Rtf = buff;
                rTB2.Invoke(action); 
                Thread.Sleep(delay);
            }
        }

        #endregion
        
        #region Вспомогательные методы и обработчики 

        // Перерасчет размеров richTextBox'ов в случае изменения размера главной формы
        void MainFormResize(object sender, EventArgs e) {
            var halfsize = (ClientSize.Width - 10) / 2;
            rTB1.Width = halfsize;
            rTB2.Width = halfsize;
            rTB2.Left = halfsize + 10;
            _BoxCapacity = CalcTextBoxCapacity();
        }

        // Расчет количества чисел, которое можно разместить в клиентской области richTextBox'ов
        // Предполагается, что оба richTextBox'а имеют одинаковые размеры и шрифт.
        int CalcTextBoxCapacity() {
            var sz = TextRenderer.MeasureText("0000h", rTB1.Font);
            return (rTB1.ClientSize.Width / sz.Width) * (rTB1.ClientSize.Height / sz.Height);
        }

        // Получение управляющих последовательностей rtf-текста, соответствующих текущим настройкам 
        // rtfTextBox'а (шрифт и его размер) и замена таблицы цветов (colortbl) на свою.
        string GetRtfHeader() {
            var i1 = rTB1.Rtf.IndexOf("{\\colortbl");   // начало colortbl
            var i2 = rTB1.Rtf.IndexOf("\\viewkind");    // конец colortbl
            var i3 = rTB1.Rtf.IndexOf("\\par\r");       // конец заголовка
            return rTB1.Rtf.Substring(0, i1) + ConstantProvider.RtfColor + rTB1.Rtf.Substring(i2, i3 - i2);
        }

        #endregion

        #region Поля класса 


        private bool    _F1_Terminate_Flag; // Флаг завершения потока Function1
        private bool    _F2_Terminate_Flag; // Флаг завершения потока Function2
        private int     _BoxCapacity;       // Количество чисел, которое можно разместить в видимой области richTextBox'а
        private string  _RtfHead;           // Заготовка с управляющими последовательностями для синтеза rtf-строки      

        #endregion
    }

    #region Класс-провайдер констант 

    class ConstantProvider {
        
        // Задержки, используемые в Function1 и Function2
        public const int Delay         = 50;        // Задержка между циклами генерации массивов случайных чисел
        public const int RareCaseDelay = 3000;      // Задержка при наступлении редкого события

        // Заготовки для сборки rtf-строки
        public const string RtfColor = @"{\colortbl ;\red0\green170\blue0;\red0\green0\blue170;\red170\green0\blue0;}";
        public const string RtfTail  = @"\par}";
        public const string RtfGreen = @"\cf1 ";
        public const string RtfBlue  = @"\cf2 ";
        public const string RtfRed   = @"\cf3 ";
    }

    #endregion
    

}
