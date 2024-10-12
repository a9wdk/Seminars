using System;
using System.Windows.Forms;

using Aladdin.HASP.Envelope;
using Aladdin.HASP.EnvelopeRuntime;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//   
//      Объектом защиты при помощи пользовательских атрибутов может быть метод, класс или вся сборка - в зависимости 
//        от того, где размещается тот или иной набор атрибутов. Список доступных атрибутов для защиты объекта: 
//
//  
// Protect           - тип BOOL, возможные значения - TRUE/FALSE, указывает нужно ли защищать объект с использованием
//                     ключа.
//
// FeatureId         - тип int, возможные значения - [0;65535], указывает номер лицензии (Feature ID), которая будет 
//                     использована при защите объекта. Принимается к исполнению, только если Protect == TRUE.
//
// Encrypt           - тип BOOL, возможные значения - TRUE/FALSE, указывает нужно ли зашифровывать CIL-код объекта.
//                     Принимается к исполнению, только если Protect == TRUE.
//
// CodeObfuscation   - тип BOOL, возможные значения - TRUE/FALSE, указывает нужно ли выполнять control_flow-обфускацию 
//                     CIL-кода объекта. Принимается к исполнению независимо от значения Protect. Данный метод защиты 
//                     приводит к снижению скорости работы защищенного кода.
//
// Frequency         - перечисляемый тип EnvelopeMethodProtectionFrequency, указывает, как часто будет проверяться
//                     лицензия для защищаемого объекта. Принимается к исполнению, только если Protect == TRUE. 
//                     Возможные значения:
//                       CheckOncePerApplicaton - однократная проверка в процессе работы приложения.
//                       CheckOncePerInstance   - однократная проверка для каждого экземпляра объекта. 
//                       CheckEveryTime         - проверка при каждом проходе управления через код объекта.
//
// SymbolObfuscation - перечисляемый тип EnvelopeSymbolObfuscation, указывает на метод обфускации символьной
//                     информации в защищаемом объекте. Принимается к исполнению независимо от значения Protect. 
//                     Возможные значения:
//                       ObfuscateSkip    - полный запрет на обфускацию всей символьной информации.
//                       ObfuscateForce   - принудительное выполнение обфускации для всей символьной информации.
//                       ObfuscateDefault - выполнять обфускацию для всей символьной информации, кроме public-имен, 
//                                          а так же, объектов с модификаторами virtual и protected. 
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Устанавливаем значения по умолчанию для всей сборки
[assembly: EnvelopeMethodProtectionAttributes(
    Protect           = false, 
    FeatureId         = 0,
    Encrypt           = false,
    CodeObfuscation   = false,
    Frequency         = EnvelopeMethodProtectionFrequency.CheckOncePerApplicaton,
    SymbolObfuscation = EnvelopeSymbolObfuscation.ObfuscateDefault )]


namespace Test_sample {

    // Устанавливаем значения по умолчанию для всего класса Program
    [EnvelopeMethodProtectionAttributes(SymbolObfuscation = EnvelopeSymbolObfuscation.ObfuscateForce )]

    static class Program {


        [STAThread]
        static void Main() {

            // Проверяем, не работают ли другие копии этого приложения
            bool FirstInstance;
            var name = "C# Sample";
            var mutex = new System.Threading.Mutex(true, name, out FirstInstance);
            if (!FirstInstance) {
                SecondCopyMsg(name);
                return;
            }
            
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            GC.KeepAlive(mutex);                                        // Защищаем mutex от сборщика мусора
        }

        static void SecondCopyMsg(string header) {
            MessageBox.Show("Another instance is already running.", header);
        }
    }
}
