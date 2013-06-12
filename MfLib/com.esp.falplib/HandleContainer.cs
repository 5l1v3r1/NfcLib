// HandleContainer.cs -*-c#-*-
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace com.esp.falplib
{
    /// <summary>
    /// GC���O�ϐ���ێ����������ׂ̃N���X
    /// </summary>
    class HandleContainer
    {
        private List<GCHandle> handleList
            = new List<GCHandle>();

        /// <summary>
        /// �ێ��ϐ��̒ǉ�
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public GCHandle AddPinnedObject(Object obj)
        {
            return GCHandle.Alloc(obj, GCHandleType.Pinned);
        }
        
        /// <summary>
        /// �ێ��ϐ��̉��
        /// </summary>
        public void FreeHandle()
        {
            foreach (GCHandle handle in handleList)
            {
                if (handle.IsAllocated)
                    handle.Free();
            }
            handleList.Clear();
        }
    }
}