package shop.mtcoding.springblogriver.post;

import org.springframework.data.domain.Page;
import shop.mtcoding.springblogriver.reply.Reply;
import shop.mtcoding.springblogriver.reply.ReplyResponse;
import shop.mtcoding.springblogriver.user.User;
import shop.mtcoding.springblogriver.user.UserResponse;

import java.time.format.DateTimeFormatter;
import java.util.List;

public class PostResponse {
    public record DTO(Integer id, String title, String content, String createdAt, String updatedAt,
                      UserResponse.DTO user, int bookmarkCount) {
        public DTO(Post post) {
            this(
                    post.getId(),
                    post.getTitle(),
                    post.getContent(),
                    post.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")),
                    post.getUpdatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")),
                    new UserResponse.DTO(post.getUser()),
                    post.getBookmarks().size()
            );
        }
    }

    public record DetailDTO(Integer id, String title, String content, String createdAt, String updatedAt,
                            int bookmarkCount, boolean isBookmark,
                            UserResponse.DTO user, ReplyResponse.PageDTO replies) {
        public DetailDTO(Post post, Page<Reply> replyPG, int sessionUserId) {
            this(
                    post.getId(),
                    post.getTitle(),
                    post.getContent(),
                    post.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")),
                    post.getUpdatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")),
                    post.getBookmarks().size(),
                    post.getBookmarks().stream().anyMatch(bookmark -> bookmark.getUser().getId() == sessionUserId),
                    new UserResponse.DTO(post.getUser()),
                    new ReplyResponse.PageDTO(replyPG)
            );
        }

    }


    public record PageDTO(boolean isFirst, boolean isLast, int pageNumber, int size, int totalPage, List<DTO> posts) {
        PageDTO(Page<Post> postPG) {
            this(postPG.isFirst(), postPG.isLast(), postPG.getNumber(), postPG.getSize(), postPG.getTotalPages(),
                    postPG.getContent().stream().map(DTO::new).toList());
        }
    }
}