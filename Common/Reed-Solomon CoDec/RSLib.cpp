//************************************************************[0x083F3C2E24]***
// Канонический кодек Рида-Соломона, адаптированный для целей защиты ПО. 
// Поддерживаются режимы RS8 и RS16, позволяющие работать с кадрами данных
// размером до 256 байт (быстро) и до 128 Кбайт (медленнее) соответственно.
// 
// RSLib.cpp - Реализация функций библиотеки RSLib, версия M.03.17
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "RSLib.h"

#define int3 _asm int 3;

static DWORD    DataLen        = 0;     // Длина данных (не в байтах, а в элементах массива!)
static DWORD    ECCLen         = 0;     // Длина ECC (не в байтах, а в элементах массива!)
static DWORD    WorkPolyLen    = 0;     // Текущее значение ECCLen/2 + 1 
static DWORD    CurGPolyDegree = 0;     // Текущая степень порождающего полинома 
static DWORD    Errors         = 0;     // Количество найденных корней полинома локаторов ошибок 
                                        // (фактически - количество найденных ошибок в кадре данных)

static HANDLE   RSHeap      = NULL;     // Куча, откуда будет распределяться память под полиномы
static GF_TYPE *nGF         = NULL;     // Нормальное поле Галуа,    длина GF_SIZE * 3
static GF_TYPE *rGF         = NULL;     // Обратное поле Галуа,      длина GF_SIZE
static GF_TYPE *GenPoly     = NULL;     // Порождающий полином,      длина ECCLen + 1
static GF_TYPE *Syndrome    = NULL;     // Полином синдрома ошибок,  длина ECCLen
static GF_TYPE *Lambda      = NULL;     // Полином локаторов ошибок, длина ECCLen/2 + 1 
static GF_TYPE *ErrorLocs   = NULL;     // Локаторы ошибок,          длина ECCLen/2 + 1
static GF_TYPE *Omega       = NULL;     // Полином величин ошибок,   длина ECCLen/2 + 1

static GF_TYPE *TmpLambda   = NULL;     // Вспомогательный полином локаторов ошибок, длина ECCLen/2 + 1
static GF_TYPE *TmpPoly     = NULL;     // Вспомогательный полином общего назначения, длина ECCLen + ECCLen/2 + 1
static GF_TYPE *TmpPolyMul  = NULL;     // Вспомогательный полином для процедуры polyMul, длина ECCLen + ECCLen/2 + 1

//================================================================================================================

// Расчет порождающего полинома для заданной длины кода ECC. Самая ресурсоёмкая функция во всей библиотеке.
// В режиме RS16, при длинах ECC, превышающих 3-4 Кбайта, при её использовании могут возникать значительные
// задержки. Пример использования библиотеки на ноутбуке с процессором Intel Pentium M 2.0 GHz (режим RS16):
// 
// Длина ECC                                                        1 Кбайт     2 Кбайта    4 Кбайта
// Расчет порождающего полинома                                     0.17 сек.   1.15 сек.   8.36 сек.
// Коррекция максимального количества ошибок (data =  16 Кбайт)     0.35 сек.   0.7  сек.   1.4  сек.
// Коррекция максимального количества ошибок (data = 124 Кбайта)    0.65 сек.   1.3  сек.   2.65 сек.
//
// Поэтому, при длинах ECC, превышающих 3-4 Кбайта более целесообразным будет не расчитывать порождающий
// полином во время работы приложения, а хранить его в готовом виде в ресурсах или данных приложения. 
// Для получения порождающего полинома в готовом виде предназначена функция RSGetGenPoly(), которую можно
// вызвать сразу после RSLibInit().
static void  CalcGenPoly(DWORD ecclen);

// Расчет локаторов ошибок и величин ошибок.
static DWORD CalcErrors(void);

// Вывод сообщения об ошибке на базе MessageBox с поддержкой спецификаторов формата и переменным числом аргументов.
static void ErrMsgBox(char *title, char *format, ...);

//================================== Операции над полиномами в полях Галуа =======================================

// Сложение полиномов
static void polyAdd(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len);
// Вычитание полиномов
static void polySub(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len);
// Масштабирование полинома 
static void polyScaling(GF_TYPE *poly, GF_TYPE factor, DWORD len);
// Сдвиг полинома на shift позиций "влево"
static void polyLShift(GF_TYPE *poly, GF_TYPE shift, DWORD len);                    
// Умножение полиномов
static void polyMul(GF_TYPE *res, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len);    
// Вычисление остатка от деления одного полинома на другой
#ifdef FULL 
static void polyRest(GF_TYPE *rest, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len);  
#endif // FULL

//=================================== Операции над числами в полях Галуа ========================================= 

#define gAdd(a, b)  (a ^ b)                                                 // Сложение 
#define gSub(a, b)  (a ^ b)                                                 // Вычитание 
#define gMul(a, b)  ((a == 0 || b == 0) ? 0 : nGF[rGF[a] + rGF[b]])         // Умножение 
#define gDiv(a, b)  ((b == 0) ? -1 : (a == 0) ? 0 : nGF[rGF[a] - rGF[b]])   // Деление 

//================================================================================================================

//////////////////////////////////////////////////////////////////////////
// Инициализация библиотеки. Проверка корректности входных параметров и приведение их к 
// размерности используемых элементов. Выделение или перераспределение динамической памяти
// для полей Галуа и всех используемых полиномов. Инициализация полей Галуа и, при
// необходимости, расчет порождающего полинома для заданной длины ECC.  
void RSLibInit(DWORD datalen, DWORD ecclen, BYTE *genpoly) {
    DWORD i, n, new_ecclen;

    // Определение длины данных и ECC (не в байтах, а в элементах массива!)
    DataLen = datalen / sizeof(GF_TYPE);
    new_ecclen = ecclen / sizeof(GF_TYPE);

    // Проверка корректности размера ECC. Для режима RS8 минимальный размер составляет 2 байта (для 
    // восстановления одного байта), для RS16 - 2 слова (4 байта) для восстановления одного слова. 
    // Данное ограничение накладывается реализацией функции polyRest().
    if(new_ecclen < 2) 
        ErrMsgBox("RSLibInit Error", "ECC size less then %d bytes!", sizeof(GF_TYPE) * 2);

    // Проверка корректности размера ECC. Для режима RS8 максимальный размер составляет 170 байт (для 
    // полного восстановления всех оставшихся 85 байт кадра), для RS16 - 43690 слов (~85 Кбайт) для 
    // полного восстановления всех оставшихся 21845 слов (~42 Kбайта) кадра. 
    if(new_ecclen > ECC_MAX) 
        ErrMsgBox("RSLibInit Error", "ECC size exceed %d bytes!", sizeof(GF_TYPE) * ECC_MAX);

    // Проверка корректности размера кадра. Размер кадра (datalen + ecclen) не должен превышать
    // размер поля Галуа (256 байт для режима RS8, 65535 слов (128 Кбайт) для RS16).
    if(DataLen + new_ecclen > GF_MAX_INDEX) 
        ErrMsgBox("RSLibInit Error", "Frame size exceed %d bytes!", SizeInBytes(GF_MAX_INDEX));

    // Проверяем, требуется ли инициализация для полей Галуа, если ECCLen == 0, то это - первый вызов
    if(ECCLen == 0) {

        // Создаём дополнительную кучу, из которой в дальнейшем будем распределять память.
        RSHeap = HeapCreate(0, (4 * GF_SIZE + 8 * ECC_MAX) * sizeof(GF_TYPE), 0);
        if(RSHeap == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for RSHeap!");

        // Выделяем память под три копии нормального поля Галуа. Это необходимо для того, чтобы
        // избежать дополнительных операций сложения и вычитания в процедурах умножения/деления
        nGF = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(GF_SIZE) * 3);
        if(nGF == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for nGF!");

        // Выделяем память под обратное поле Галуа
        rGF = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(GF_SIZE));
        if(rGF == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for rGF!");

        // Базовая копия - средняя
        nGF += GF_MAX_INDEX;

        // Генерация нормального поля Галуа для базовой копии
        for(i = nGF[0] = 1, nGF[GF_MAX_INDEX] = 0; i < GF_MAX_INDEX; i++) {
            n = nGF[i-1] << 1;
            if(n < GF_MAX_INDEX) nGF[i] = (GF_TYPE)n; 
                else nGF[i] = (GF_TYPE)(n ^ INIT_POLY);
        }
    
        // Генерация обратного поля Галуа
        for(i = 0; i < GF_SIZE; i++) rGF[nGF[i]] = (GF_TYPE)i; 

        // Заполнение остальных двух копий нормального поля Галуа значениями из базовой копии. 
        for(i = 0; i < GF_MAX_INDEX; i++) nGF[i - GF_MAX_INDEX] = nGF[i + GF_MAX_INDEX] = nGF[i];

    } else {

        // Это уже не первый вызов, инициализация полей Галуа не требуется. Если такая же длина ECC была 
        // в прошлой сессии, то не требуется, также, перерасчет порождающего полинома и перераспределение 
        // динамической памяти под прочие полиномы. 
        
        if(ECCLen == new_ecclen) return;

        HeapFree(RSHeap, 0, TmpPolyMul);  TmpPolyMul = NULL;
        HeapFree(RSHeap, 0, TmpPoly);     TmpPoly    = NULL;
        HeapFree(RSHeap, 0, Omega);       Omega      = NULL;
        HeapFree(RSHeap, 0, ErrorLocs);   ErrorLocs  = NULL;
        HeapFree(RSHeap, 0, TmpLambda);   TmpLambda  = NULL;
        HeapFree(RSHeap, 0, Lambda);      Lambda     = NULL;
        HeapFree(RSHeap, 0, Syndrome);    Syndrome   = NULL;
        HeapFree(RSHeap, 0, GenPoly);     GenPoly    = NULL;
    }
    
    ECCLen = new_ecclen;
    WorkPolyLen = ECCLen/2 + 1;

    // Выделяем память под порождающий полином
    GenPoly = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(ECCLen + 1));
    if(GenPoly == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for GenPoly!");

    // Выделяем память под полином синдрома ошибок
    Syndrome = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(ECCLen));
    if(Syndrome == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Syndrome!");
    
    // Выделяем память под полином локаторов ошибок
    Lambda = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
    if(Lambda == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Lambda!");
    
    // Выделяем память под вспомогательный полином локаторов ошибок
    TmpLambda = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
    if(TmpLambda == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpLambda!");

    // Выделяем память под локаторы ошибок
    ErrorLocs = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
    if(ErrorLocs == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for ErrorLocs!");
    
    // Выделяем память под полином величин ошибок 
    Omega = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
    if(Omega == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Omega!");
    
    // Выделяем память под вспомогательный полином общего назначения
    TmpPoly = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen + ECCLen));
    if(TmpPoly == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpPoly!");
    
    // Выделяем память под вспомогательный полином для процедуры polyMul
    TmpPolyMul = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen + ECCLen));
    if(TmpPolyMul == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpPolyMul!");

    // Расчет порождающего полинома для заданной длины ECC или использование ранее сохраненного.
    if(genpoly == NULL) CalcGenPoly(ECCLen); 
        else CopyMemory(GenPoly, genpoly, ecclen + 1);
}

#ifdef FULL 

//////////////////////////////////////////////////////////////////////////
// Расчет кода коррекции ошибок для заданной длины ECC.
void RSCalcECC(BYTE *data, BYTE *ecc) {
    polyRest((GF_TYPE *)ecc, (GF_TYPE *)data, DataLen, GenPoly, ECCLen+1);
}

#endif // FULL

//////////////////////////////////////////////////////////////////////////
// Синдромный декодер, осуществляющий проверку целостности кадра данных (data + ecc). 
// Расчет полинома синдрома ошибок выполняется путем подстановки в проверяемый полином 
// кадра данных, корней порождающего полинома. Если кадр данных не поврежден, то корни 
// порождающего полинома будут так же и его корнями, при подстановке которых он обращается в нуль.
DWORD RSCheckData(BYTE *data, BYTE *ecc) {
    DWORD i, j, sum;

    // Расчет полинома синдрома ошибок для кадра данных (data+ecc)
    for(i = 0; i < ECCLen; i++) {
        sum = 0;
        for(j = 0; j < DataLen; j++) sum = gAdd(((GF_TYPE *)data)[j], gMul(nGF[i+1], sum));
        for(j = 0; j < ECCLen;  j++) sum = gAdd(((GF_TYPE *)ecc)[j],  gMul(nGF[i+1], sum));
        Syndrome[i] = (GF_TYPE)sum;
    }

    // Проверка коэффициентов полинома синдрома ошибок на равенство нулю. 
    // Если хотя бы один из них не равен нулю - целостность кадра нарушена.
    for(i = 0; i < ECCLen; i++) if(Syndrome[i] != 0) return(1);     // Есть ошибки.
    return(0);                                                      // Нет ошибок.
}

//////////////////////////////////////////////////////////////////////////
// Восстановление измененных элементов кадра данных
DWORD RSRepairData(BYTE *data, BYTE *ecc) { 
    DWORD i, j, k, r, err, num, denom;

    if(!CalcErrors()) return(0);        // не удалось вычислить полином локаторов, слишком много ошибок
 
    for(r = 0; r < Errors; r++) {
        i = ErrorLocs[r];
        for(k = ECCLen/2, num = j = 0; j < k; j++) 
            num = gAdd(num, gMul(Omega[j], nGF[((GF_MAX_INDEX - i) * j) % GF_MAX_INDEX]));
        for(j = 1, denom = 0; j < WorkPolyLen; j += 2) 
            denom = gAdd(denom, gMul(Lambda[j], nGF[((GF_MAX_INDEX - i) * (j - 1)) % GF_MAX_INDEX]));
        err = gMul(num, nGF[GF_MAX_INDEX - rGF[denom]]);
        k = DataLen + ECCLen - i - 1;
        if(k < DataLen) ((GF_TYPE *)data)[k] ^= err;    // коррекция ошибок в массиве данных
            else ((GF_TYPE *)ecc)[k - DataLen] ^= err;  // коррекция ошибок в массиве ECC
    }
    return(1);      // все ошибки исправлены
}

//////////////////////////////////////////////////////////////////////////
// Освобождение динамической памяти и прочих ресурсов
void RSLibClose(void) {
    DataLen = ECCLen = WorkPolyLen = CurGPolyDegree = Errors = 0;
    if(RSHeap != NULL) {
        if(HeapDestroy(RSHeap)) RSHeap = NULL;
            else ErrMsgBox("RSLibClose Error", "Can't destroy RSHeap!");
    }   
}

///////////////////////////////////////////////////////////////////////////////
// Расчет порождающего полинома для заданной длины ECC. Максимальная степень
// полинома r = ECCLen, соответственно, длина полинома равна ECCLen + 1 (в 
// элементах а не в байтах!!!). Корнями полинома являются элементы поля Галуа,
// соответствующие результатам возведения числа 2 в степени 1, 2, ..., r (т.е. 
// 2^1, 2^2, ..., 2^r). При подстановке этих корней полином обращается в нуль.
static void CalcGenPoly(DWORD ecclen) {
    DWORD gpolylen = ecclen + 1, gpolyleninbytes = SizeInBytes(gpolylen);
    GF_TYPE tmp[2] = { 0, 1 };
    
    ZeroMemory(GenPoly, gpolyleninbytes);
    for(CurGPolyDegree = GenPoly[0] = 1; CurGPolyDegree < gpolylen; CurGPolyDegree++) {
        tmp[0] = nGF[CurGPolyDegree];
        polyMul(TmpPoly, GenPoly, gpolylen, tmp, 2);
        CopyMemory(GenPoly, TmpPoly, gpolyleninbytes);
    }
}

//////////////////////////////////////////////////////////////////////////
// Расчет полинома локаторов ошибок и вычисление самих локаторов ошибок. Проверка
// корректности найденных локаторов ошибок. Расчет полинома величин ошибок.
static DWORD CalcErrors(void) { 
    DWORD i, q, m, L1, L2, dscr, zero; 
    
    // Расчет полинома локаторов ошибок по алгоритму Берлекэмпа-Месси (Berlekamp-Massey). 
    // Переменные алгоритма:
    // q    - номер шага алгоритма.
    // m    - номер шага, на котором полином локаторов последний раз модифицировался.
    // Lx   - количество членов в левой части уравнений (фактически - количество искаженных.
    //        элементов кадра данных, предполагаемое во время итераций алгоритма).
    // dscr - значение невязки (сумма левой и правой части q-го уравнения, если полином
    //        локаторов удовлетворяет уравнению).
    // Полиномы алгоритма:
    // Lambda    - рассчитываемый полином локаторов ошибок.
    // TmpLambda - вспомогательный полином локаторов ошибок.
    // TmpPoly   - вспомогательный полином, используемый при модификации полинома локаторов
    //             ошибок для "подстройки" его под уравнения системы.

    ZeroMemory(Lambda, SizeInBytes(WorkPolyLen));           
    Lambda[0] = 1;
    CopyMemory(TmpPoly, Lambda, SizeInBytes(WorkPolyLen));  
    
    for(m = -1, q = L1 = 0; q < ECCLen; q++) {
        polyLShift(TmpPoly, 1, q);
        for(dscr = i = 0; i <= L1; i++) dscr = gAdd(dscr, gMul(Lambda[i], Syndrome[q-i]));
        if(dscr) {
            for(i = 0; i < WorkPolyLen; i++) TmpLambda[i] = gAdd(Lambda[i], gMul(dscr, TmpPoly[i]));
            if(L1 < (q - m)) {
                L2 = q - m;
                m  = q - L1;
                L1 = L2;
                for(i = 0; i < WorkPolyLen - 1; i++) TmpPoly[i] = gMul(Lambda[i], nGF[GF_MAX_INDEX - rGF[dscr]]);
            }   
            CopyMemory(Lambda, TmpLambda, SizeInBytes(WorkPolyLen)); 
        }
    }

    // Процедура Ченя (Chien search). Нахождение корней полинома локаторов ошибок и вычисление локаторов ошибок.  
    
    for(q = 1, Errors = 0; q < GF_SIZE; q++) {
        for(zero = i = 0; i < WorkPolyLen; i++) zero = gAdd(zero, gMul(nGF[(i * q) % GF_MAX_INDEX], Lambda[i]));
        if(zero == 0) ErrorLocs[Errors++] = (GF_TYPE)(GF_MAX_INDEX - q); 
    }
    
    // Проверка корректности полинома локаторов ошибок. Если полином локаторов был рассчитан 
    // верно, то количество найденных корней (Errors) должно быть равно степени полинома 
    // локаторов ошибок (L1), а сами локаторы не должны укзывать за границу кадра данных.
    
    if(L1 != Errors) return(0); 
    m = DataLen + ECCLen;
    for(i = 0; i < Errors; i++) if(ErrorLocs[i] >= m) return(0); 
        
    // Расчет полинома величин ошибок

    polyMul(TmpPoly, Lambda, WorkPolyLen - 1, Syndrome, ECCLen);
    ZeroMemory(Omega, SizeInBytes(WorkPolyLen));
    CopyMemory(Omega, TmpPoly, SizeInBytes(WorkPolyLen));

    return(1);
}

//////////////////////////////////////////////////////////////////////////
// Сложение полиномов poly1 и poly2 в поле Галуа, результат помещается в массив res. Если полиномы разной 
// длины, то в параметре len указывается размер самого длинного из них (в элементах, а не в байтах!!!).
static void polyAdd(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len) { 
    for(DWORD i = 0; i < len; i++) res[i] = gAdd(poly1[i], poly2[i]); 
}

//////////////////////////////////////////////////////////////////////////
// Вычитание полиномов poly1 и poly2 в поле Галуа, результат помещается в массив res. Если полиномы разной 
// длины, то в параметре len указывается размер самого длинного из них (в элементах, а не в байтах!!!).
static void polySub(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len) { 
    for(DWORD i = 0; i < len; i++) res[i] = gSub(poly1[i], poly2[i]); 
}

//////////////////////////////////////////////////////////////////////////
// Масштабирование полинома в поле Галуа на factor, длина исходного полинома - len элементов 
static void polyScaling(GF_TYPE *poly, GF_TYPE factor, DWORD len) { 
    for(DWORD i = 0; i < len; i++) poly[i] = gMul(poly[i], factor); 
}

//////////////////////////////////////////////////////////////////////////
// Сдвиг полинома на shift позиций "влево", длина исходного полинома - len, результата - (len + shift) элементов
// Пример сдвига на shift = 2 позиции: 3x^2+2x^1+1x^0 -> 3x^4+2x^3+1x^2+0x^1+0x^0 -> 3x^4+2x^3+1x^2
static void polyLShift(GF_TYPE *poly, GF_TYPE shift, DWORD len) { 
    for(DWORD i = len - 1; i < len; i--) poly[i + shift] = poly[i]; 
    ZeroMemory(poly, SizeInBytes(shift));
}

///////////////////////////////////////////////////////////////////////////////
// Умножение полиномов poly1 и poly2 в поле Галуа, длина результата равна сумме длин полиномов-множителей 
// Длины полиномов задаются в количестве элементов массива, а не в байтах!!!
static void polyMul(GF_TYPE *res, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len) {
    ZeroMemory(res, SizeInBytes(p1len + p2len));
    for(DWORD i = 0; i < p1len; i++) {
        CopyMemory(TmpPolyMul, poly2, SizeInBytes(p2len));
        polyScaling(TmpPolyMul, poly1[i], p2len);
        polyLShift(TmpPolyMul, (GF_TYPE)i, p2len);
        polyAdd(res, res, TmpPolyMul, p2len + i);
    }
}

#ifdef FULL 

//////////////////////////////////////////////////////////////////////////
// Вычисление остатка от деления poly1 на poly2, длина результата равна p2len-1.
// Длины полиномов задаются в количестве элементов массива, а не в байтах!!!
// Длина poly2 не должна быть менее 2-х элементов (т.е. ECCLen >= 2). 
static void polyRest(GF_TYPE *rest, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len) {
    DWORD i, j, tmp;

    ZeroMemory(TmpPoly, SizeInBytes(p2len));
    p2len -= 2;
    for(i = 0; i < p1len; i++) {
        tmp = gSub(poly1[i], TmpPoly[p2len]);
        for(j = p2len; j > 0; j--) TmpPoly[j] = gSub(TmpPoly[j - 1], gMul(poly2[j], tmp));
        TmpPoly[0] = gMul(poly2[0], tmp);
    }
    for(tmp = p2len + 1, i = 0; i < tmp; i++) rest[i] = TmpPoly[p2len - i];
}

#endif // FULL

//////////////////////////////////////////////////////////////////////////
// Получение информации о количестве исправленных ошибок. Если требуется, то
// вызывать нужно после функции RSRepairData() 
DWORD RSGetErrors() {
    return(Errors);
}

//////////////////////////////////////////////////////////////////////////
// Функция возвращает процент готовности расчета порождающего полинома. Актуально в 
// режиме RS16 при длине ЕСС более 3-4 Кбайт для контроля состояния процесса, т.к. расчет
// в этом случае может занять значительное время. Вызывать её следует из другого потока, 
// с момента передачи управления в функцию RSLibInit() и до момента возврата управления
// из неё. В любое другое время использование RSGenPolyPercentReady() лишено смысла. 
DWORD RSGenPolyPercentReady(void) {
    DWORD res;
    
    if(ECCLen == 0) return(0);
    res = SizeInBytes(CurGPolyDegree) / (SizeInBytes(ECCLen + 1) / 100); 
    return( (res > 100) ? 100 : res );
}

//////////////////////////////////////////////////////////////////////////
// Функция сохраняет расчитанный порождающий полином в указанный массив, длина в байтах равна
// SizeInBytes(ECCLen + 1). Сохраненный полином в дальнейшем может использоваться сразу, а не 
// генерироваться при инициализации библиотеки. Вызывать её следует после функции RSLibInit(),
// но до вызова функции RSLibClose().
void RSGetGenPoly(BYTE *genpoly) {
    if(genpoly != NULL) CopyMemory(genpoly, GenPoly, SizeInBytes(ECCLen + 1));
}

///////////////////////////////////////////////////////////////////////////
// Вывод сообщения об ошибке на базе MessageBox с поддержкой спецификаторов формата и переменным числом аргументов.
static void ErrMsgBox(char *title, char *format, ...) {
    char buffer[1024];
    va_list arg_ptr;
    
    va_start(arg_ptr, format);
    vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
    va_end(arg_ptr);
    MessageBox(NULL, buffer, title, MB_SYSTEMMODAL | MB_ICONERROR);
    exit(1);
}
