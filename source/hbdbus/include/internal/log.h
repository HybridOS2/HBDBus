/**
 * @file log.h
 * @author Vincent Wei (https://github.com/VincentWei)
 * @date 2023/05/10
 * @brief Log facilities.
 *
 * Copyright (c) 2023 FMSoft (http://www.fmsoft.cn)
 *
 * This file is part of HBDBus.
 *
 * HBDBus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HBDBus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#ifndef _HBDBUS_INTERNAL_LOG_H_
#define _HBDBUS_INTERNAL_LOG_H_

#include <purc/purc-helpers.h>

#ifdef NDEBUG
#   define LOG_DEBUG(x, ...)
#else
#   define LOG_DEBUG(x, ...)   \
    purc_log_debug("%s: " x, __func__, ##__VA_ARGS__)
#endif /* not defined NDEBUG */

#ifdef LOG_ERR
#   undef LOG_ERR
#endif

#define LOG_ERR(x, ...)   \
    purc_log_error("%s: " x, __func__, ##__VA_ARGS__)

#define LOG_WARN(x, ...)    \
    purc_log_warn("%s: " x, __func__, ##__VA_ARGS__)

#define LOG_NOTE(x, ...)    \
    purc_log_notice("%s: " x, __func__, ##__VA_ARGS__)

#define LOG_INFO(x, ...)    \
    purc_log_info("%s: " x, __func__, ##__VA_ARGS__)

#endif /* not defined _HBDBUS_INTERNAL_LOG_H_ */

