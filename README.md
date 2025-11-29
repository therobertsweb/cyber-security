Perfecto, vamos a hacerlo bien ordenado para que todos tus archivos lleguen a tu repo de GitHub.

Ahora mismo el problema es este:
La carpeta

/home/kali/Desktop/clase_de_python

no es un repositorio de git, por eso te sale

fatal: not a git repository (or any of the parent directories): .git

La forma más limpia y segura es:
	1.	Clonar tu repositorio de GitHub
	2.	Copiar dentro de ese repositorio todos los archivos de clase_de_python
	3.	Hacer commit y push

Voy paso a paso.
	1.	Ir al escritorio

En tu terminal:

cd /home/kali/Desktop

	2.	Clonar tu repositorio de GitHub

Usa la misma URL que ya usaste antes. Por lo que mostraste, debe ser algo así:

git clone git@github.com:therobertsweb/cyber-security.git

Si usas https, sería algo tipo:

git clone https://github.com/therobertsweb/cyber-security.git

Esto va a crear la carpeta:

/home/kali/Desktop/cyber-security
	3.	Entrar al repositorio clonado

cd /home/kali/Desktop/cyber-security

	4.	Copiar todos los archivos de tu carpeta clase_de_python dentro del repo

cp -r ../clase_de_python/. .

Explicación rápida:
../clase_de_python/. es el contenido de la carpeta clase_de_python
. es la carpeta actual, que ahora mismo es cyber-security
	5.	Verificar que los archivos están ahí

ls

Deberías ver algo como:

README.md  Seccion_exploit_5  Seccion_Vulnerabilidades_4  Section_MAN_in_the_middle_6  Seccion_buscadores_1  Seccion_scan_3  Section_Aplicaiones_web_7  Section_Post_Explotacion_8
	6.	Ver el estado de git

git status

Ahora sí debes ver los archivos como nuevos sin seguir.
	7.	Agregar todos los archivos al commit

git add .

	8.	Crear el commit

git commit -m "Agregar archivos de clase_de_python al repositorio"

	9.	Enviar todo a GitHub

git push origin main

Si tu rama principal se llama diferente, por ejemplo master, cambiarías main por master.
	10.	Confirmar en GitHub

Abre tu repositorio en GitHub en el navegador y deberías ver todas las carpetas y archivos que tenías en clase_de_python.

Si en algún paso te aparece un error específico, copia el mensaje exacto y me lo pegas y lo corregimos al vuelo.
