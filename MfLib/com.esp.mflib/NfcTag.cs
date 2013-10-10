using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;

using com.esp.nfclib;
using com.esp.common;

namespace com.esp.nfclib.card
{
    /// <summary>
    /// カード種別
    /// </summary>
    public enum CardType
    {
        /// <summary>不明</summary>
        Unknown,
        /// <summary>Felica</summary>
        Felica,
        /// <summary>Mifare(1K)</summary>
        Mifare1K,
        /// <summary>Mifare(4K)</summary>
        Mifare4K,
        /// <summary>Mifare(UL)</summary>
        MifareUL,
        /// <summary>Ntag203</summary>
        Ntag203,
    }

    /// <summary>
    /// Nfc基底
    /// </summary>
    public abstract class NfcTag
    {
        /// <summary>Mifareライブラリ</summary>
        protected NfcLib lib;

        /// <summary>UID</summary>
        public byte[] Uid { get; protected set; }

        /// <summary>CardType</summary>
        public CardType CardType { get; protected set; }

        /// <summary>
        /// NfcLibを指定して生成
        /// </summary>
        /// <param name="lib">NfcLib</param>
        /// <param name="uid">UID</param>
        public NfcTag(NfcLib lib, byte[] uid)
        {
            this.lib = lib;
            Uid = uid;
            CardType = card.CardType.Unknown;
        }

        /// <summary>
        /// カードの解放
        /// </summary>
        public virtual void Release()
        {
            lib.StopAccess();
        }    }

    /// <summary>
    /// Mifare Card
    /// </summary>
    public abstract class Mifare:NfcTag
    {
        /// <summary>
        /// Mifareカードの生成
        /// </summary>
        /// <param name="lib"></param>
        /// <param name="uid"></param>
        public Mifare(NfcLib lib, byte[] uid)
            :base(lib, uid)
        {

        }
        /// <summary>
        /// データブロックへの書き込み
        /// </summary>
        /// <param name="blockOrPage">ブロック又はページ番号</param>
        /// <param name="buffer">データバッファ[CL:16Byte,UL:4Byte]</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public virtual void Write(byte blockOrPage, byte[] buffer, int offset)
        {
            lib.WriteBlockData(blockOrPage, buffer, offset);
        }

        /// <summary>
        /// データブロックからの読み出し
        /// </summary>
        /// <param name="blockOrPage">ブロック又はページ番号</param>
        /// <param name="buffer">データバッファ[16Byte]</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public virtual void Read(byte blockOrPage, byte[] buffer, int offset)
        {
            lib.ReadBlockData(blockOrPage, buffer, offset);
        }

        /// <summary>
        /// ブロックへの認証
        /// </summary>
        /// <param name="useA">'A'/'B'</param>
        /// <param name="block">アクセス対象ブロック番号</param>
        /// <param name="key">認証鍵[6Byte]</param>
        public virtual void Authentication(bool useA, byte block, byte[] key)
        {
            lib.Authentication(useA, block, key);
        }
    }

    /// <summary>
    /// Mifare Classic 1K
    /// </summary>
    public class MifareCL:Mifare
    {
        /// <summary>
        /// NfcLibを指定して生成
        /// </summary>
        /// <param name="lib">NfcLib</param>
        /// <param name="uid">UID</param>
        public MifareCL(NfcLib lib, byte[] uid)
            :base(lib, uid)
        {
            CardType = card.CardType.Mifare1K;
        }
    }

    /// <summary>
    /// Mifare Classic 4K
    /// </summary>
    public class MifareCL4K : MifareCL
    {
        /// <summary>
        /// NfcLibを指定して生成
        /// </summary>
        /// <param name="lib">NfcLib</param>
        /// <param name="uid">UID</param>
        public MifareCL4K(NfcLib lib, byte[] uid)
            :base(lib, uid)
        {
            CardType = card.CardType.Mifare4K;
        }
    }

    /// <summary>
    /// Mifare Ultralight
    /// </summary>
    public class MifareUL:Mifare
    {
        /// <summary>
        /// NfcLibを指定して生成
        /// </summary>
        /// <param name="lib">NfcLib</param>
        /// <param name="uid">UID</param>
        public MifareUL(NfcLib lib, byte[] uid)
            :base(lib, uid)
        {
            CardType = card.CardType.MifareUL;
        }

        /// <summary>
        /// データブロックへの書き込み
        /// </summary>
        /// <param name="page">ページ番号</param>
        /// <param name="buffer">データバッファ[4Byte]</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public override void Write(byte page, byte[] buffer, int offset)
        {
            lib.WritePageData(page, buffer, offset);
        }
    }

    /// <summary>
    /// NTAG203
    /// </summary>
    public class NTAG203 : Mifare
    {
        /// <summary>
        /// NfcLibを指定して生成
        /// </summary>
        /// <param name="lib">NfcLib</param>
        /// <param name="uid">UID</param>
        public NTAG203(NfcLib lib, byte[] uid)
            : base(lib, uid)
        {
            CardType = card.CardType.Ntag203;
        }

        /// <summary>
        /// データブロックへの書き込み
        /// </summary>
        /// <param name="page">ページ番号</param>
        /// <param name="buffer">データバッファ[4Byte]</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public override void Write(byte page, byte[] buffer, int offset)
        {
            lib.WritePageData(page, buffer, offset);
        }
    }

    /// <summary>
    /// Felica
    /// </summary>
    public class Felica : NfcTag
    {
        /// <summary>
        /// FeliCa
        /// </summary>
        /// <param name="lib">ライブラリ</param>
        /// <param name="idm">iDm</param>
        public Felica(NfcLib lib, byte[] idm)
            :base(lib, idm)
        {
            CardType = card.CardType.Felica;
        }

        /// <summary>
        /// ランダムブロックへの書き込み
        /// </summary>
        /// <param name="svCode">サービスコード</param>
        /// <param name="block">ブロックリスト</param>
        /// <param name="buffer">データバッファ</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public void Write(ushort svCode, int[] block, byte[] buffer, int offset)
        {
            lib.WriteBlockData(svCode, block, buffer, offset);
        }

        /// <summary>
        /// ランダムブロックへの書き込み
        /// </summary>
        /// <param name="svCode">サービスコード</param>
        /// <param name="block">ブロックリスト</param>
        /// <param name="buffer">データバッファ</param>
        /// <param name="offset">バッファ内の開始位置</param>
        /// <param name="length">長さ[16の倍数]</param>
        public void Write(ushort svCode, int block, byte[] buffer, int offset, int length)
        {
            int blocks = length / NfcLib.FC_BLOCK_LENGTH;
            int[] blockList = new int[blocks];
            for (int i = 0; i < blocks; i++)
            {
                blockList[i] = block + i;
            }
            lib.WriteBlockData(svCode, blockList, buffer, offset);
        }


        /// <summary>
        /// ランダムブロックの読込み
        /// </summary>
        /// <param name="svCode">サービスコード</param>
        /// <param name="block">ブロックリスト</param>
        /// <param name="buffer">データバッファ</param>
        /// <param name="offset">バッファ内の開始位置</param>
        public void Read(ushort svCode, int[] block, byte[] buffer, int offset)
        {
            lib.ReadBlockData(svCode, block, buffer, offset);
        }

        /// <summary>
        /// ランダムブロックの読込み
        /// </summary>
        /// <param name="svCode">サービスコード</param>
        /// <param name="block">ブロックリスト</param>
        /// <param name="buffer">データバッファ</param>
        /// <param name="offset">バッファ内の開始位置</param>
        /// <param name="length">長さ[16の倍数]</param>
        public void Read(ushort svCode, int block, byte[] buffer, int offset, int length)
        {
            int blocks = length / NfcLib.FC_BLOCK_LENGTH;
            int[] blockList = new int[blocks];
            for (int i = 0; i < blocks; i++)
            {
                blockList[i] = block + i;
            }
            lib.ReadBlockData(svCode, blockList, buffer, offset);
        }
    }
}
