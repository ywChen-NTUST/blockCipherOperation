install:
	sudo apt-get install python3.7
	sudo apt install python3-pip
	pip install Pillow==7.1.2
	pip install pycryptodome==3.10.1
	pip install numpy==1.19.5

enc: enc.py
	python3 enc.py -key aHczQjEwNzE1MDI5 -iv aHczQjEwNzE1MDQx

dec: dec.py
	python3 dec.py --key aHczQjEwNzE1MDI5 --iv aHczQjEwNzE1MDQx --mode ECB
	python3 dec.py --key aHczQjEwNzE1MDI5 --iv aHczQjEwNzE1MDQx --mode CTR
	python3 dec.py --key aHczQjEwNzE1MDI5 --iv aHczQjEwNzE1MDQx --mode Custom
