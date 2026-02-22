# Compiler and flags
CC = clang
CFLAGS = -Wall -Wextra -g -Isrc

# Directories
SRC_DIR = src
TEST_SRC_DIR = test/src
BUILD_DIR = build
TEST_BUILD_DIR = test/build

# --- Common Source Files ---
# These are shared by both the main app and the tests
COMMON_SRCS = $(SRC_DIR)/dyn.c \
              $(SRC_DIR)/err.c \
			  $(SRC_DIR)/lex.c \
 			  $(SRC_DIR)/map.c \
			  $(SRC_DIR)/nodes.c \
              $(SRC_DIR)/strings.c 

# Create object file names for common sources (e.g., build/map.o)
COMMON_OBJS = $(COMMON_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# --- Main Application Config ---
MAIN_SRC = $(SRC_DIR)/main.c
MAIN_OBJ = $(BUILD_DIR)/main.o
MAIN_TARGET = $(BUILD_DIR)/app

# --- Test Suite Config ---
TEST_SRCS = $(wildcard $(TEST_SRC_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_SRC_DIR)/%.c=$(TEST_BUILD_DIR)/%.o)
TEST_BINS = $(TEST_SRCS:$(TEST_SRC_DIR)/%.c=$(TEST_BUILD_DIR)/%)

# --- Targets ---

# Default target: builds the main application
all: $(MAIN_TARGET)
tests: $(TEST_BINS)

test_nodes: $(TEST_BUILD_DIR)/nodes_test
	@valgrind --quiet --error-exitcode=1 --leak-check=full --show-leak-kinds=all --track-origins=yes $(TEST_BUILD_DIR)/nodes_test || exit 1;
	@echo "Test passed."

# Rule to build the main application
# Links common objects + main.o
$(MAIN_TARGET): $(COMMON_OBJS) $(MAIN_OBJ)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Build successful: $(MAIN_TARGET)"

# Rule to build the tests
# Links common objects + map_test.o
$(TEST_BUILD_DIR)/%: $(TEST_BUILD_DIR)/%.o $(COMMON_OBJS)
	@mkdir -p $(TEST_BUILD_DIR)
	@$(CC) $(CFLAGS) $^ -o $@
	@echo "Test compiled: $@"

# --- Compilation Rules ---

# Compile source files from src/ into build/
# This handles map.c, strings.c, AND main.c
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BUILD_DIR)/%.o: $(TEST_SRC_DIR)/%.c
	@mkdir -p $(TEST_BUILD_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@


# --- Utilities ---

# Loop through all test binaries and run them
run_tests: tests
	@echo "--- Beginning testing. ---"
	@for test in $(TEST_BINS); do \
		echo "[ Running $$test... ]"; \
		valgrind --quiet --error-exitcode=1 --leak-check=full --show-leak-kinds=all --track-origins=yes ./$$test 	|| exit 1; \
	done
	@echo "--- All tests passed. ---"

.PHONY: all tests run_tests