## Recuperación sin el dispositivo

Si el dispositivo principal se pierde completamente, la clave (`meshKey`) puede ser recuperada usando los métodos `recoverMeshKeyFromShares` y `importMeshKey`. Para que esta recuperación sea exitosa, es necesario contar con **dos de los tres shares** (cualquier par entre el share 1, 2 y 3).

El share del dispositivo por sí solo no es suficiente para recuperar la clave. Estos métodos permiten reconstruir la clave en un nuevo dispositivo y reemplazar la anterior.
