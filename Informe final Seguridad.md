# Informe final de Seguridad
Este es el informe del proyecto final del curso Seguridad. Nuestro proyecto fue un firmador de archivos y verificador de firmas.

### ¿Cómo hicieron el programa?
Lo primero que hicimos después de escoger el proyecto fue releerlo nuevamente para entender bien qué era lo que nos pedían y de esa forma no perder tiempo haciendo mal el trabajo. Luego, buscamos la API criptográfica de Java para conocer su funcionamiento y tutoriales sobre cómo usarla. En este caso utilizamos la API o el paquete "javax.crypto" para realizar los cifrados y la API "Security" para creación de llaves pública y privadas, firmar archivos y verificar las firmas.

Después de esto, nos repartimos el trabajo para poder avanzar mejor. Uno hizo el generador de claves protegidas con contraseña, otro hizo la verificación de la firma y entre los dos hicimos el generador de firmas, ya que este involucraba los otros dos puntos. De igual manera, siempre estuvimos en comunicación para entender el código que se realizaba del otro lado, incluso hubo varias reuniones virtuales para avanzar en los puntos asignados individualmente.

Sin embargo, tuvimos algunos inconvenientes en el desarrollor y nuestra primera versión del software no se pudo completar en su totalidad, así que decidimos reeplantear la lógica planificada y acomodarnos mejor para realizar el desarrollo completo en compañía.

Por último realizamos algunas pruebas para verificar que todo estaba funcionando correctamente.

### ¿Qué dificultades tuvieron?

* Una de las principales dificultades fue el poco manejo de las librerías y API que se involucran para la solución de estos temas. Ya que nos tocó leer y ver bastantes vídeos para poder entender la lógica de las librerías y así hacer el mejor uso de estas y no estar haciendo el uso incorrecto de las herramientas.
* Presentamos un error persistente llamado "Illegar base64 character 2e", el cual nos obligó a cambiar la lógica de nuestros métodos que habíamos planificado en un principio. Al parecer es un error dentro de los valores que acepta el método implementado para la codificación, sin embargo, ninguna de las soluciones de diferentes foros funcionó.
#### Imagen del error presentado

![](https://github.com/ASuarez10/FileSignerAndVerifier/blob/main/recursos/Error%20Base64.jpeg?raw=true)

* También tuvimos un problema con el encriptado del archivo ya que no queria aceptar la contraseña de ninguna forma. Aparecía un error el cual indicaba que la contraseña debía tener una cantidad de bytes multiplo de 16, pero nunca aceptó nada.
#### Imagen del error presentado

![](https://github.com/ASuarez10/FileSignerAndVerifier/blob/main/recursos/Error%20Base64.jpeg?raw=true)

### Conclusiones
* Es una experiencia enriquecedora ya que nos permitió entender a fondo cómo funcionan algunas aplicaciones a un nivel de código, también nos permitió aplicar los conocimientos aprendidos durante el semestre en este tema.
* El conocimiento en teoría siempre es muy necesario, ya que fue el principal motivo por el cual el proyecto pudo salir adelante, debido a que nos ayudó a entender las librerías que íbamos a usar y cómo plantear la lógica de sus métodos.
