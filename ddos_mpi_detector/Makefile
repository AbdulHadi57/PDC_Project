# Makefile for DDoS MPI Detector

CC = mpicc
CFLAGS = -Wall -Wextra -O2 -std=c11 -Iinclude
LDFLAGS = -lm -lpcap
SRCDIR = src
OBJDIR = obj
BINDIR = bin
INCLUDEDIR = include

# Source files
UTILS_SRC = $(SRCDIR)/utils/common_utils.c
CORE_SRC = $(SRCDIR)/core/csv_parser.c
DETECTOR_SRC = $(SRCDIR)/detectors/entropy_detector.c \
               $(SRCDIR)/detectors/pca_detector.c \
               $(SRCDIR)/detectors/cusum_detector.c
ORCHESTRATOR_SRC = $(SRCDIR)/core/orchestrator.c \
                   $(SRCDIR)/core/mpi_comm.c \
                   $(SRCDIR)/core/metrics.c
MITIGATION_SRC = $(SRCDIR)/mitigation/mitigation_engine.c
CAPTURE_SRC = $(SRCDIR)/capture/live_capture.c

# Object files
UTILS_OBJ = $(OBJDIR)/common_utils.o
CORE_OBJ = $(OBJDIR)/csv_parser.o $(OBJDIR)/mpi_comm.o $(OBJDIR)/metrics.o
DETECTOR_OBJ = $(OBJDIR)/entropy_detector.o $(OBJDIR)/pca_detector.o $(OBJDIR)/cusum_detector.o
ORCHESTRATOR_OBJ = $(OBJDIR)/orchestrator.o
MITIGATION_OBJ = $(OBJDIR)/mitigation_engine.o
CAPTURE_OBJ = $(OBJDIR)/live_capture.o

ALL_OBJ = $(UTILS_OBJ) $(CORE_OBJ) $(DETECTOR_OBJ) $(MITIGATION_OBJ) $(CAPTURE_OBJ)

# Main executable
MAIN_TARGET = $(BINDIR)/ddos_orchestrator

# Targets
.PHONY: all clean directories help

all: directories $(MAIN_TARGET)

directories:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p results

$(MAIN_TARGET): $(ALL_OBJ) $(ORCHESTRATOR_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete!"

# Object file compilation rules
$(OBJDIR)/common_utils.o: $(SRCDIR)/utils/common_utils.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/csv_parser.o: $(SRCDIR)/core/csv_parser.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/mpi_comm.o: $(SRCDIR)/core/mpi_comm.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/metrics.o: $(SRCDIR)/core/metrics.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/entropy_detector.o: $(SRCDIR)/detectors/entropy_detector.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/pca_detector.o: $(SRCDIR)/detectors/pca_detector.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/cusum_detector.o: $(SRCDIR)/detectors/cusum_detector.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/orchestrator.o: $(SRCDIR)/core/orchestrator.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/mitigation_engine.o: $(SRCDIR)/mitigation/mitigation_engine.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/live_capture.o: $(SRCDIR)/capture/live_capture.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "Clean complete!"

help:
	@echo "DDoS MPI Detector - Build System"
	@echo "================================"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build all components (default)"
	@echo "  clean      - Remove all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make           # Build the project"
	@echo "  make clean     # Clean build files"
	@echo ""
	@echo "Run Example:"
	@echo "  mpirun -np 4 ./bin/ddos_orchestrator --mode dataset --input dataset.csv"
