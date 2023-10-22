# Project Name
PROJECT_NAME = Project_CTR

# Project Relative Paths
PROJECT_PATH = $(CURDIR)
PROJECT_PROGRAM_LOCAL_DIR = ctrtool makerom

# Detect Platform
ifeq ($(PROJECT_PLATFORM),)
	ifeq ($(OS), Windows_NT)
		export PROJECT_PLATFORM = WIN32
	else
		UNAME = $(shell uname -s)
		ifeq ($(UNAME), Darwin)
			export PROJECT_PLATFORM = MACOS
		else
			export PROJECT_PLATFORM = GNU
		endif
	endif
endif

# Detect Architecture
ifeq ($(PROJECT_PLATFORM_ARCH),)
	ifeq ($(PROJECT_PLATFORM), WIN32)
		export PROJECT_PLATFORM_ARCH = x86_64
	else ifeq ($(PROJECT_PLATFORM), GNU)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else ifeq ($(PROJECT_PLATFORM), MACOS)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else
		export PROJECT_PLATFORM_ARCH = x86_64
	endif
endif

# all is the default, user should specify what the default should do
#	- 'deps' for building local dependencies.
#	- 'program' for building executable programs.
all: progs
	
clean: clean_progs

# Programs
.PHONY: progs
progs:
	@$(foreach prog,$(PROJECT_PROGRAM_LOCAL_DIR), cd "$(prog)" && $(MAKE) deps program && cd "$(PROJECT_PATH)";)

.PHONY: clean_progs
clean_progs:
	@$(foreach prog,$(PROJECT_PROGRAM_LOCAL_DIR), cd "$(prog)" && $(MAKE) clean_deps clean && cd "$(PROJECT_PATH)";)