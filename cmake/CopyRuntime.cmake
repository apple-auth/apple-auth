foreach(dll IN LISTS DLLS)
    file(COPY "${dll}" DESTINATION "${DESTINATION}")
endforeach()
