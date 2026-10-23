# Portability gate for iat_repair_test.cpp: the file must stay free of
# Windows/unicorn specifics (the repair pipeline is engine-native; the
# Windows-only corpus acceptance sits in its own #ifdef section and uses the
# public capture header). Same boundary discipline as the CI include gates.
file(READ "${GATE_FILE}" content)
if(content MATCHES "windows\\.h")
    message(FATAL_ERROR "iat_repair_test.cpp must not reference windows.h")
endif()
if(content MATCHES "unicorn/")
    message(FATAL_ERROR "iat_repair_test.cpp must not reference unicorn headers")
endif()
