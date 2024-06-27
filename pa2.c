#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

void save_cmds(char *input, char *cmds[4]);
int determine_redirection_type(char *cmd);
int determine_cmd_type(char *cmd);
int generate_args(char *args[10], char cmds[200], const char *delimiter);
int validate_args(char *cmd);
void print_error(char *cmd);

void execute_cmd(char *args[10]);
void execute_head(char **args);
void execute_tail(char **args);
void execute_cat(char **args);
void execute_mv(char **args);
void execute_rm(char **args);
void execute_cp(char **args);
void execute_cd(char **args);
void execute_pwd();
void execute_exit(char **args);

int main() {
    size_t size;
    int num_cmds, num_pipeline, redirection_type;
    int stdin_copy = dup(STDIN_FILENO);
    int stdout_copy = dup(STDOUT_FILENO);
    char prev_cmd[200];

    while(1) {
        char *input = NULL;

        signal(SIGINT,SIG_IGN);
		signal(SIGTSTP,SIG_IGN);

        getline(&input, &size, stdin);
        if (input[strlen(input) - 1] == '\n' || input[strlen(input) - 1] == EOF)
            input[strlen(input) - 1] = '\0';

        if(strcmp(input, "quit") == 0)
            break;
        else if (strcmp(input, "\0") == 0)
            continue;

        // Pipe 기준으로 Command 개수 count
        int count = 1;
        for (int i = 0; i < strlen(input); i++) {
            if (input[i] == '|')
                count++;
        }
        num_cmds = count;

        // pipe 기준으로 자른 command들
        char *cmds[num_cmds];
        save_cmds(input, cmds);

        if (num_cmds == 1) {  // no pipes
            // cmd를 space 기준으로 자른 것
            char *args[200];
            int redirection_type = determine_redirection_type(cmds[0]);

            if (redirection_type == 1) {
                generate_args(args, cmds[0], " ");
                if (validate_args(args[0]) == 0) {
                    free(input);
                    printf("swsh: Command not found\n");
                    continue;
                }

                int cmd_type = determine_cmd_type(args[0]);

                if (cmd_type == 1) {
                    int pid;
                    if ((pid = fork()) == 0) {
                        pid_t c_pid = getpid();
                        setpgid(0, c_pid);

                        signal(SIGINT, SIG_DFL);
                        signal(SIGTSTP, SIG_DFL);

                        execute_cmd(args);
                    } else {
                        int status;
                        waitpid(pid, &status, 0);
                    }
                } else {
                    execute_cmd(args);
                }
            } else if (redirection_type == 2) {
                int args_len = generate_args(args, cmds[0], "< ");
                if (validate_args(args[0]) == 0) {
                    free(input);
                    printf("swsh: Command not found\n");
                    continue;
                }

                int cmd_type = determine_cmd_type(args[0]);

                int in = open(args[args_len - 1], O_RDONLY);
                if (in == -1) {
                    fprintf(stdout, "%s: %s\n", args[0], strerror(errno));
                    free(input);
                    continue;
                }
                dup2(in, STDIN_FILENO);
                close(in);

                args[args_len - 1] = NULL;

                if (cmd_type == 1) {
                    int pid;
                    if ((pid = fork()) == 0) {
                        pid_t c_pid = getpid();
                        setpgid(0, c_pid);

                        signal(SIGINT, SIG_DFL);
                        signal(SIGTSTP, SIG_DFL);

                        execute_cmd(args);
                    } else {
                        int status;
                        waitpid(pid, &status, 0);
                    }
                } else {
                    execute_cmd(args);
                }
                // clearerr(stdin);
            } else if (redirection_type == 3 || redirection_type == 4) {
                int args_len = generate_args(args, cmds[0], "> ");
                if (validate_args(args[0]) == 0) {
                    free(input);
                    printf("swsh: Command not found\n");
                    continue;
                }

                int cmd_type = determine_cmd_type(args[0]);

                int out;
                if (redirection_type == 3)
                    out = open(args[args_len - 1], O_RDWR | O_CREAT | O_TRUNC, 0644);
                else if (redirection_type == 4)
                    out = open(args[args_len - 1], O_RDWR | O_CREAT | O_APPEND, 0644);
                if (out == -1) {
                    fprintf(stdout, "%s: %s\n", args[0], strerror(errno));
                    free(input);
                    continue;
                }
                dup2(out, STDOUT_FILENO);
                close(out);

                args[args_len - 1] = NULL;

                if (cmd_type == 1) {
                    int pid;
                    if ((pid = fork()) == 0) {
                        pid_t c_pid = getpid();
                        setpgid(0, c_pid);

                        signal(SIGINT, SIG_DFL);
                        signal(SIGTSTP, SIG_DFL);

                        execute_cmd(args);
                    } else {
                        int status;
                        waitpid(pid, &status, 0);
                    }
                } else {
                    execute_cmd(args);
                }
            } else {
                int args_len = generate_args(args, cmds[0], "<> ");
                if (validate_args(args[0]) == 0) {
                    free(input);
                    printf("swsh: Command not found\n");
                    continue;
                }

                int cmd_type = determine_cmd_type(args[0]);

                int in = open(args[args_len - 2], O_RDONLY);
                if (in == -1) {
                    fprintf(stdout, "%s: %s\n", args[0], strerror(errno));
                    free(input);
                    continue;
                }
                dup2(in, STDIN_FILENO);
                close(in);

                int out = open(args[args_len - 1], O_RDWR | O_CREAT | O_TRUNC, 0644);
                if (out == -1) {
                    fprintf(stdout, "%s: %s\n", args[0], strerror(errno));
                    free(input);
                    continue;
                }
                dup2(out, STDOUT_FILENO);
                close(out);

                args[args_len - 1] = NULL;
                args[args_len - 2] = NULL;

                if (cmd_type == 1) {
                    int pid;
                    if ((pid = fork()) == 0) {
                        pid_t c_pid = getpid();
                        setpgid(0, c_pid);

                        signal(SIGINT, SIG_DFL);
                        signal(SIGTSTP, SIG_DFL);

                        execute_cmd(args);
                    } else {
                        int status;
                        waitpid(pid, &status, 0);
                    }
                } else {
                    execute_cmd(args);
                }
            }

            dup2(stdin_copy, STDIN_FILENO);
            dup2(stdout_copy, STDOUT_FILENO);
        } else {  // with pipes
            char *args[num_cmds][200];
            int fd[2 * (num_cmds - 1)];
            int redirection_type[4], cmd_type[4], args_len[num_cmds];
            int continue_flag = 0, fdd = 0;

            // 각 Command의 args, redirection_type, args_len, cmd_type 저장
            for (int i = 0; i < num_cmds; i++) {
                char *cmds_copy = malloc(strlen(cmds[i]) + 1);
                strcpy(cmds_copy, cmds[i]);
                redirection_type[i] = determine_redirection_type(cmds[i]);

                int j = 0;
                char *token = strtok(cmds_copy, " ");
                while (token != NULL) {
                    args[i][j++] = strdup(token);
                    token = strtok(NULL, "<> ");
                }
                args[i][j] = NULL;
                args_len[i] = j;

                // printf("args[%d][0]: %s\n", i, args[i][0]);

                if (validate_args(args[i][0]) == 0) {
                    printf("swsh: Command not found\n");
                    free(input);
                    free(cmds_copy);
                    continue_flag = 1;
                    break;
                }

                cmd_type[i] = determine_cmd_type(args[i][0]);

                free(cmds_copy);
            }

            // 사용자가 입력한 Command가 처리하지 않는 Command일 경우 실행 취소
            if (continue_flag)
                continue;

            // pipe 생성
            for (int i = 0; i < num_cmds - 1; i++)
                pipe(fd + i * 2);

            // 첫 번째 Command부터 순차적으로 실행
            for (int i = 0; i < num_cmds; i++) {
                int pid;
                if ((pid = fork()) == 0) {
                    pid_t parent_pid = getpid();
                    setpgid(0, parent_pid);

                    signal(SIGINT, SIG_DFL);
                    signal(SIGTSTP, SIG_DFL);

                    if (i < num_cmds - 1)
                        dup2(fd[i * 2 + 1], STDOUT_FILENO);
                    if (fdd != 0)
                        dup2(fdd, STDIN_FILENO);

                    for (int j = 0; j < 2 * (num_cmds - 1); j++)
                        close(fd[j]);
                    
                    // Command 실행
                    if (redirection_type[i] == 1) {
                        if (cmd_type[i] == 1) {
                            int cpid;
                            if ((cpid = fork()) == 0) {
                                setpgid(0, parent_pid);
                                execute_cmd(args[i]);
                                fprintf(stdout, "%s: %d\n", args[i][0], errno);
                                fflush(stdout);
                            } else {
                                int status;
                                waitpid(cpid, &status, 0);
                            }
                        } else {
                            execute_cmd(args[i]);
                        }
                    } else if (redirection_type[i] == 2) {
                        int in = open(args[i][args_len[i] - 1], O_RDONLY);
                        if (in == -1) {
                            fprintf(stdout, "%s: %s\n", args[i][0], strerror(errno));
                            free(input);
                            continue;
                        }
                        dup2(in, STDIN_FILENO);
                        close(in);

                        args[i][args_len[i] - 1] = NULL;

                        if (cmd_type[i] == 1) {
                            int cpid;
                            if ((cpid = fork()) == 0) {
                                setpgid(0, parent_pid);
                                execute_cmd(args[i]);
                                fprintf(stdout, "%s: %d\n", args[i][0], errno);
                                fflush(stdout);
                            } else {
                                int status;
                                waitpid(cpid, &status, 0);
                            }
                        } else {
                            execute_cmd(args[i]);
                        }

                        dup2(stdin_copy, STDIN_FILENO);
                    } else if (redirection_type[i] == 3 || redirection_type[i] == 4) {
                        int out;
                        if (redirection_type[i] == 3)
                            out = open(args[i][args_len[i] - 1], O_RDWR | O_CREAT | O_TRUNC, 0644);
                        else if (redirection_type[i] == 4)
                            out = open(args[i][args_len[i] - 1], O_RDWR | O_CREAT | O_APPEND, 0644);
                        if (out == -1) {
                            fprintf(stdout, "%s: %s\n", args[i][0], strerror(errno));
                            free(input);
                            continue;
                        }
                        dup2(out, STDOUT_FILENO);
                        close(out);

                        args[i][args_len[i] - 1] = NULL;

                        if (cmd_type[i] == 1) {
                            int cpid;
                            if ((cpid = fork()) == 0) {
                                setpgid(0, parent_pid);
                                execute_cmd(args[i]);
                                fprintf(stdout, "%s: %d\n", args[i][0], errno);
                                fflush(stdout);
                            } else {
                                int status;
                                waitpid(cpid, &status, 0);
                            }
                        } else {
                            execute_cmd(args[i]);
                        }

                        dup2(stdout_copy, STDOUT_FILENO);
                    } else {
                        int in = open(args[i][args_len[i] - 2], O_RDONLY);
                        if (in == -1) {
                            fprintf(stdout, "%s: %s\n", args[i][0], strerror(errno));
                            free(input);
                            continue;
                        }
                        dup2(in, STDIN_FILENO);
                        close(in);

                        int out = open(args[i][args_len[i] - 1], O_RDWR | O_CREAT | O_TRUNC, 0644);
                        if (out == -1) {
                            fprintf(stdout, "%s: %s\n", args[i][0], strerror(errno));
                            free(input);
                            continue;
                        }
                        dup2(out, STDOUT_FILENO);
                        close(out);

                        args[i][args_len[i] - 1] = NULL;
                        args[i][args_len[i] - 2] = NULL;

                        if (cmd_type[i] == 1) {
                            int cpid;
                            if ((cpid = fork()) == 0) {
                                setpgid(0, parent_pid);
                                execute_cmd(args[i]);
                                fprintf(stdout, "%s: %d\n", args[i][0], errno);
                                fflush(stdout);
                            } else {
                                int status;
                                waitpid(cpid, &status, 0);
                            }
                        } else {
                            execute_cmd(args[i]);
                        }

                        dup2(stdin_copy, STDIN_FILENO);
                        dup2(stdout_copy, STDOUT_FILENO);
                    }
                    exit(0);
                } else {
                    int status;
                    waitpid(pid, &status, 0);

                    if (fdd != 0)
                        close(fdd);
                    if (i < num_cmds - 1)
                        close(fd[i * 2 + 1]);

                    fdd = fd[i * 2];
                }

                char c;
                while ((c = getchar()) != EOF && c != '\n');
            }

            // close file descriptors
            for (int i = 0; i < 2 * (num_cmds - 1); i++)
                close(fd[i]);
        }

        free(input);
    }

    close(stdin_copy);
    close(stdout_copy);

    return 0;
}

void save_cmds(char *input, char *cmds[4]) {
    int i = 0;
    char *ptr = strtok(input, "|");
    while (ptr != NULL) {
        cmds[i++] = ptr;
        ptr = strtok(NULL, "|");
    }
}
int determine_redirection_type(char *cmd) {
    int found_input_redirection = 0;
    for (int i = 0; i < strlen(cmd); i++) {
        if (cmd[i] == '<')
            found_input_redirection = 1;
        else if (cmd[i] == '>') {
            if (cmd[i + 1] == '>')
                return 4;
            else if (found_input_redirection == 1)
                return 5;
            else
                return 3;
        }
    }
    if (found_input_redirection == 1)
        return 2;
    else
        return 1;
}
int determine_cmd_type(char *cmd) {
    if (strcmp(cmd, "ls") == 0 ||
        strcmp(cmd, "man") == 0 ||
        strcmp(cmd, "grep") == 0 ||
        strcmp(cmd, "sort") == 0 ||
        strcmp(cmd, "awk") == 0 ||
        strcmp(cmd, "bc") == 0 ||
        strncmp(&cmd[0], "./", 2) == 0
    ) {
        return 1;
    } else if (
        strcmp(cmd, "head") == 0 ||
        strcmp(cmd, "tail") == 0 ||
        strcmp(cmd, "cat") == 0
    ) {
        return 2;
    } else if (
        strcmp(cmd, "mv") == 0 ||
        strcmp(cmd, "rm") == 0 ||
        strcmp(cmd, "cp") == 0 ||
        strcmp(cmd, "cd") == 0
    ) {
        return 3;
    } else if (
        strcmp(cmd, "pwd") == 0 ||
        strcmp(cmd, "exit") == 0
    ) {
        return 4;
    }
    return 0;
}
int generate_args(char *args[10], char cmds[200], const char *delimiter) {
    if (strncmp(cmds, "awk", 3) == 0) {
        // char dest[30] = "\"";
        int idx = strcspn(cmds, "'");
        char *second_arg = (char *) malloc(strlen(cmds) + 1);
        second_arg[0] = '\0';
        for (int i = idx + 1; cmds[i] != '\'' && cmds[i] != '\0'; i++) {
            strncat(second_arg, &cmds[i], 1);
        }
        // strcat(dest, second_arg);
        // strcat(dest, "\"");

        // printf("dest: %s\n", dest);

        args[0] = "awk";
        args[1] = second_arg;
        // args[1] = dest;

        char *token = strtok(cmds, " ");
        while (token != NULL) {
            token = strtok(NULL, " ");
            if (token != NULL)
                args[2] = token;
        }

        args[3] = NULL;

        free(second_arg);

        return 3;
    } else {
        int k = 0;
        char *ptr = strtok(cmds, delimiter);
        while (ptr != NULL) {
            args[k++] = ptr;
            ptr = strtok(NULL, delimiter);
        }
        args[k] = NULL;

        return k;
    }
}
int validate_args(char *cmd) {
    if (strcmp(cmd, "ls") == 0 ||
        strcmp(cmd, "man") == 0 ||
        strcmp(cmd, "grep") == 0 ||
        strcmp(cmd, "sort") == 0 ||
        strcmp(cmd, "awk") == 0 ||
        strcmp(cmd, "bc") == 0 || 
        strcmp(cmd, "head") == 0 || 
        strcmp(cmd, "tail") == 0 ||
        strcmp(cmd, "cat") == 0 ||
        strcmp(cmd, "mv") == 0 ||
        strcmp(cmd, "rm") == 0 ||
        strcmp(cmd, "cp") == 0 ||
        strcmp(cmd, "cd") == 0 ||
        strcmp(cmd, "pwd") == 0 ||
        strcmp(cmd, "exit") == 0 ||
        strncmp(cmd, "./", 2) == 0
    )
        return 1;
    else
        return 0;
}
void print_error(char *cmd) {
    if (errno == EACCES)
        fprintf(stdout, "%s: %s\n", cmd, strerror(EACCES));
    else if (errno == EISDIR)
        fprintf(stdout, "%s: %s\n", cmd, strerror(EISDIR));
    else if (errno == ENOENT)
        fprintf(stdout, "%s: %s\n", cmd, strerror(ENOENT));
    else if (errno == ENOTDIR)
        fprintf(stdout, "%s: %s\n", cmd, strerror(ENOTDIR));
    else if (errno == EPERM)
        fprintf(stdout, "%s: %s\n", cmd, strerror(EPERM));
    else
        fprintf(stdout, "Error occured: %d\n", errno);
}

void execute_cmd(char *args[10]) {
    if (strcmp(args[0], "head") == 0)
        execute_head(args);
    else if (strcmp(args[0], "tail") == 0)
        execute_tail(args);
    else if (strcmp(args[0], "cat") == 0)
        execute_cat(args);
    else if (strcmp(args[0], "mv") == 0)
        execute_mv(args);
    else if (strcmp(args[0], "rm") == 0)
        execute_rm(args);
    else if (strcmp(args[0], "cp") == 0)
        execute_cp(args);
    else if (strcmp(args[0], "cd") == 0)
        execute_cd(args);
    else if (strcmp(args[0], "pwd") == 0)
        execute_pwd();
    else if (strcmp(args[0], "exit") == 0)
        execute_exit(args);
    else {
        execvp(args[0], args);
        fprintf(stdout, "Error occured: %d\n", errno);
        exit(EXIT_FAILURE);
    }
    fflush(stdout);
}
void execute_head(char **args) {
    int fd = STDIN_FILENO;
    int lines = 10;
    int line_count = 0;
    char buf[1024];

    if (args[1]) {
        if (strcmp(args[1], "-n") == 0) {
            lines = atoi(args[2]);
            if (args[3]) {
                fd = open(args[3], O_RDONLY);
            }
        } else {
            fd = open(args[1], O_RDONLY);
        }
    }

    if (fd < 0) {
        print_error(args[0]);
        return;
    }

    ssize_t bytes_read;
    int i = 0;
    while (line_count < lines && (bytes_read = read(fd, buf + i, 1)) > 0) {
        if (buf[i] == '\n') {
            line_count++;
        }

        if (line_count == lines || buf[i] == '\n') {
            write(STDOUT_FILENO, buf, i + 1);
            i = -1;
        }

        i++;
    }

    if (fd != STDIN_FILENO)
        close(fd);
}
void execute_tail(char **args) {
    int fd = STDIN_FILENO;
    int lines = 10;
    long file_size;
    char buf[1024];
    int line_count = 0;
    off_t pos;

    if (args[1]) {
        if (strcmp(args[1], "-n") == 0) {
            lines = atoi(args[2]);
            if (args[3]) {
                fd = open(args[3], O_RDONLY);
            }
        } else {
            fd = open(args[1], O_RDONLY);
        }
    }

    if (fd < 0) {
        print_error(args[0]);
        return;
    }

    file_size = lseek(fd, 0, SEEK_END);

    memset(buf, 0, sizeof(buf));

    for (pos = file_size - 1; pos >= 0; pos--) {
        lseek(fd, pos, SEEK_SET);
        read(fd, buf, 1);

        if (buf[0] == '\n') {
            line_count++;
            if (line_count == lines + 1)
                break;
        }
    }

    if (line_count < lines || pos == 0)
        pos = 0;
    else
        pos++;

    lseek(fd, pos, SEEK_SET);
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        write(STDOUT_FILENO, buf, bytes_read);
    }

    if (fd != STDIN_FILENO)
        close(fd);
}
void execute_cat(char **args) {
    int fd = STDIN_FILENO;
    char buf[1024];

    if (args[1]) {
        fd = open(args[1], O_RDONLY);
        if (fd < 0) {
            print_error(args[0]);
            return;
        }
    }

    ssize_t bytes_read;
    while ((bytes_read = read(fd, buf, 1024)) > 0) {
        write(STDOUT_FILENO, buf, bytes_read);
    }

    if (fd != STDIN_FILENO)
        close(fd);
}
void execute_mv(char **args) {
    if (access(args[1], F_OK) == -1) {
        fprintf(stdout, "mv: %s\n", strerror(ENOENT));
        return;
    }
    if (access(args[1], R_OK) == -1) {
        fprintf(stdout, "mv: %s\n", strerror(EACCES));
        return;
    }
    if (access(args[2], F_OK) != -1) {
        fprintf(stdout, "mv: %s\n", strerror(EEXIST));
        return;
    }

    rename(args[1], args[2]);
}
void execute_rm(char **args) {
    int i = 1;
    while (args[i] != NULL) {
        if (access(args[i], F_OK) == -1) {
            fprintf(stdout, "mv: %s\n", strerror(ENOENT));
            return;
        }
        if (access(args[i], R_OK) == -1) {
            fprintf(stdout, "mv: %s\n", strerror(EACCES));
            return;
        }
        unlink(args[i++]);
    }
}
void execute_cp(char **args) {
    if (access(args[1], F_OK) == -1) {
        fprintf(stdout, "cp: %s\n", strerror(ENOENT));
        return;
    }
    if (access(args[2], F_OK) != -1) {
        fprintf(stdout, "Error occured: %d\n", EEXIST);
        return;
    }

    struct stat path1_stat;
    int args_stat = stat(args[1], &path1_stat);
    if (args_stat == -1) {
        fprintf(stdout, "Error occured: %d\n", errno);
        return;
    }
    if (S_ISDIR(path1_stat.st_mode)) {
        fprintf(stdout, "cp: %s\n", strerror(EISDIR));
        return;
    }

    FILE *sourceFile = fopen(args[1], "r");
    if (!sourceFile) {
        print_error(args[0]);
        return;
    }
    FILE *destFile = fopen(args[2], "w");
    if (!destFile) {
        print_error(args[0]);
        fclose(sourceFile);
        return;
    }

    char buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, 1024, sourceFile)) > 0) {
        fwrite(buffer, 1, bytesRead, destFile);
    }

    fclose(sourceFile);
    fclose(destFile);
}
void execute_cd(char **args) {
    int result = chdir(args[1]);
    if (result == -1) {
        fprintf(stdout, "Error occured: %d\n", errno);
        return;
    }
}
void execute_pwd() {
    char *buffer = (char *) malloc(sizeof(char) * 1024);
    getcwd(buffer, 1024);
    printf("%s\n", buffer);
    free(buffer);
}
void execute_exit(char **args) {
    int status = 0;
    if (args[1])
        status = atoi(args[1]);
    printf("exit\n");
    fflush(stdout);
    exit(status);
}
